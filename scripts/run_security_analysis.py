#!/usr/bin/env python3
"""
The AI Release Intelligence Engine. Takes one already-validated, canonical
final_release_context.json and produces an executive Markdown report.

This is the ONLY AI step in the entire pipeline. Per the frozen
architecture: Python owns every deterministic computation upstream of
this (normalization, aggregation, domain classification, statistics,
provenance) — this script's only job is to call the model once with that
already-complete evidence and the system prompt, and write whatever comes
back. It does not parse, re-derive, or validate the security content of
the response — that would be exactly the kind of "AI reinterpreting
deterministic facts" the system prompt explicitly forbids the MODEL from
doing, and it would be just as wrong for this script to do it either.

The one thing this script DOES check deterministically: whether the
report's Final Recommendation section actually contains one of the four
allowed values. That's a cheap, mechanical format check — not a judgment
about whether the recommendation is correct — and it's a separate concern
from the AI's instructions, the same way a linter checking "did this PR
include a Final Recommendation heading" is different from reviewing
whether the recommendation itself is sound.

UNVALIDATED AGAINST A REAL API CALL — same caveat every other piece of
this pipeline started with. No Anthropic API key was available in the
environment this was built in (confirmed: api.anthropic.com is reachable
from that sandbox, returns 401 with no credentials — a network path
exists, credentials don't). Built correctly against the documented
Messages API shape, but the first real invocation is what actually proves
this, the same way every other script in this pipeline only became
trustworthy after a real run surfaced and fixed something. Share the
first real release_report.md (and, if anything looks off, the raw API
response) the same way every other "first real run" got handled this
session.

Usage:
    run_security_analysis.py --release-context final_release_context.json \\
        --system-prompt scripts/system_prompt.md \\
        --output release_report.md \\
        [--model claude-sonnet-4-6] [--max-tokens 8192]

Requires ANTHROPIC_API_KEY in the environment.
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error

API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

# Matches the four values mandated by the system prompt's Final
# Recommendation section — checked mechanically after the fact, not
# something this script tells the model (that instruction lives entirely
# in system_prompt.md, this is just a format sanity check on the result).
ALLOWED_RECOMMENDATIONS = (
    "APPROVE WITH CONDITIONS",  # checked before the plain "APPROVE" substring it contains
    "MANUAL REVIEW REQUIRED",
    "DO NOT APPROVE",
    "APPROVE",
)


def load_text(path):
    with open(path, "r") as f:
        return f.read()


def call_claude(system_prompt, release_context_json, model, max_tokens, api_key):
    user_message = (
        "Analyze the following final_release_context.json and produce the "
        "Release Intelligence Report exactly as specified in your "
        "instructions — the full 9-section Markdown document, ending in "
        "exactly one Final Recommendation.\n\n"
        "```json\n"
        f"{release_context_json}\n"
        "```"
    )

    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_message}],
    }

    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        print(f"FATAL: Anthropic API returned HTTP {e.code}: {error_body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"FATAL: could not reach the Anthropic API: {e.reason}", file=sys.stderr)
        sys.exit(1)

    text_blocks = [block["text"] for block in body.get("content", []) if block.get("type") == "text"]
    if not text_blocks:
        print(
            f"FATAL: API response had no text content. Full response: "
            f"{json.dumps(body, indent=2)}",
            file=sys.stderr,
        )
        sys.exit(1)

    return "".join(text_blocks), body


def check_recommendation_format(report_text):
    """Mechanical format check only — see module docstring for why this
    isn't a judgment call about the recommendation's correctness."""
    for value in ALLOWED_RECOMMENDATIONS:
        if value in report_text:
            return value
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--release-context", required=True)
    parser.add_argument("--system-prompt", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--model", default=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
        help="Defaults to claude-sonnet-4-6 (or $ANTHROPIC_MODEL) — a deliberate cost/quality "
             "tradeoff for a job that runs on every release; claude-opus-4-7 is the upgrade "
             "path if report quality, not cost, turns out to be the binding constraint.",
    )
    parser.add_argument("--max-tokens", type=int, default=8192)
    args = parser.parse_args()

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print(
            "FATAL: ANTHROPIC_API_KEY is not set. This is a hard requirement, not something "
            "to default around — there is no meaningful fallback for 'skip the AI analysis'.",
            file=sys.stderr,
        )
        sys.exit(1)

    system_prompt = load_text(args.system_prompt)
    release_context_json = load_text(args.release_context)

    # Sanity-check the input is at least valid JSON before spending an API
    # call on it — fail fast and cheap rather than send malformed input to
    # the model and get back a confused report.
    try:
        parsed = json.loads(release_context_json)
    except json.JSONDecodeError as e:
        print(f"FATAL: {args.release_context} is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    finding_count = len(parsed.get("findings", []))
    print(f"Analyzing {finding_count} findings from {args.release_context} (model: {args.model})...")

    report_text, raw_response = call_claude(
        system_prompt, release_context_json, args.model, args.max_tokens, api_key
    )

    with open(args.output, "w") as f:
        f.write(report_text)

    usage = raw_response.get("usage", {})
    print(f"Wrote report -> {args.output} ({len(report_text)} chars)")
    print(f"  tokens: {usage.get('input_tokens', '?')} in / {usage.get('output_tokens', '?')} out")
    print(f"  stop_reason: {raw_response.get('stop_reason', '?')}")
    if raw_response.get("stop_reason") == "max_tokens":
        print(
            "  ::warning:: stopped at max_tokens — the report was very likely truncated "
            "mid-section. Re-run with a higher --max-tokens.",
            file=sys.stderr,
        )

    recommendation = check_recommendation_format(report_text)
    if recommendation:
        print(f"  Final Recommendation detected: {recommendation}")
    else:
        print(
            "  ::warning:: none of the four required Final Recommendation values "
            "(APPROVE / APPROVE WITH CONDITIONS / MANUAL REVIEW REQUIRED / DO NOT APPROVE) "
            "were found in the report text. This is a format check only, not a content "
            "judgment — but a human should look at the raw report before trusting it.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()