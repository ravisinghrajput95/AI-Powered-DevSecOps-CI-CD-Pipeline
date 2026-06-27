#!/usr/bin/env python3
"""
The AI Release Intelligence Engine. Takes one already-validated, canonical
final_release_context.json and produces a structured ExecutiveReport.json
— the canonical AI reasoning contract. Does NOT produce Markdown/HTML —
that's the Renderer's job (see render_report.py), a separate component
downstream of this one, per the frozen three-layer separation:
ReleaseContext -> AI Release Intelligence -> ExecutiveReport.json -> Renderer.

Gets structured output via forced tool-use (tool_choice pinned to a single
tool, submit_executive_report), not by asking the model to emit JSON in
its text response. This is a deliberate reliability choice: free-text JSON
risks preamble, code-fence wrapping, or truncation mid-object; a forced
tool call doesn't.

The tool's input_schema is DERIVED from executive_report.schema.json at
runtime (the AI-authored subset: executive_summary, cross_domain_
correlations, top_risks, priority_actions, release_readiness,
assumptions_and_unknowns) rather than hand-duplicated — one schema, one
source of truth, no drift between what the tool accepts and what the
final artifact is validated against.

Three deterministic things happen AFTER the model responds, none of which
are the model's job:
1. Python adds report_id/generated_at/release_context_ref — the model
   never invents its own identifier for its own output.
2. The COMPLETE object (model output + Python-added fields) is validated
   against executive_report.schema.json. A schema violation is a hard
   failure, not a warning — an ExecutiveReport that doesn't conform isn't
   safe for any renderer to consume.
3. Every finding_id cited in any supporting_evidence/blocking_evidence
   array is checked against the REAL finding_id set in
   final_release_context.json. This exists because of a real, observed
   failure: the first real run of this engine cited the same finding
   twice with two slightly different finding_ids (a transposed-character
   transcription error re-typing a 12-char hex string from memory). A
   forced-tool-call schema constrains SHAPE (12 hex chars) but not
   EXISTENCE (a real finding's actual id) — this check catches what the
   schema can't.

UNVALIDATED AGAINST A REAL TOOL-USE API CALL specifically — the prior
free-text version of this script WAS validated against a real run (see
git history / prior release_report.md). This tool-use rewrite changes the
request shape (tools + tool_choice) but not the auth/network path, which
was already confirmed working. Same expectation as every other "first
real run" this pipeline has had: share the first real executive_report.json
(and raw API response, if anything looks off) so this can be fixed against
real output the same way every other piece was.

Usage:
    run_security_analysis.py --release-context final_release_context.json \\
        --system-prompt scripts/system_prompt.md \\
        --schema scripts/executive_report.schema.json \\
        --output executive_report.json \\
        [--model claude-sonnet-4-6] [--max-tokens 8192]

Requires ANTHROPIC_API_KEY in the environment.
"""
import argparse
import hashlib
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

try:
    import jsonschema
except ImportError:
    print(
        "FATAL: the 'jsonschema' package is required (pip install jsonschema). "
        "Hand-rolling JSON Schema validation would reinvent a well-solved problem "
        "poorly — this is a deliberate dependency, not an oversight.",
        file=sys.stderr,
    )
    sys.exit(1)

API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
TOOL_NAME = "submit_executive_report"

# The Python-owned fields — never part of the tool's input_schema, always
# added after the model responds. See module docstring point 1.
PYTHON_OWNED_FIELDS = {"schema_version", "report_id", "generated_at", "release_context_ref"}

FINDING_ID_PATTERN_FIELDS = ("supporting_evidence", "blocking_evidence")


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def load_text(path):
    with open(path, "r") as f:
        return f.read()


def build_tool_schema(full_schema):
    """Derive the tool's input_schema from executive_report.schema.json —
    the AI-authored subset only. One schema, no hand-duplicated second
    copy that could drift from it."""
    ai_properties = {k: v for k, v in full_schema["properties"].items() if k not in PYTHON_OWNED_FIELDS}
    ai_required = [k for k in full_schema["required"] if k not in PYTHON_OWNED_FIELDS]
    return {
        "type": "object",
        "required": ai_required,
        "additionalProperties": False,
        "properties": ai_properties,
    }


def call_claude(system_prompt, release_context_json, tool_schema, model, max_tokens, api_key):
    user_message = (
        "Analyze the following final_release_context.json and call "
        f"{TOOL_NAME} with your complete ExecutiveReport analysis, exactly "
        "as specified in your instructions.\n\n"
        "```json\n"
        f"{release_context_json}\n"
        "```"
    )

    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_message}],
        "tools": [
            {
                "name": TOOL_NAME,
                "description": (
                    "Submit the completed ExecutiveReport analysis of the provided "
                    "final_release_context.json. Call this exactly once, with every "
                    "required field populated."
                ),
                "input_schema": tool_schema,
            }
        ],
        "tool_choice": {"type": "tool", "name": TOOL_NAME},
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

    tool_use_blocks = [b for b in body.get("content", []) if b.get("type") == "tool_use" and b.get("name") == TOOL_NAME]
    if not tool_use_blocks:
        print(
            f"FATAL: no {TOOL_NAME} tool_use block in the response despite forced "
            f"tool_choice. Full response: {json.dumps(body, indent=2)}",
            file=sys.stderr,
        )
        sys.exit(1)
    if len(tool_use_blocks) > 1:
        print(
            f"::warning:: model called {TOOL_NAME} {len(tool_use_blocks)} times; "
            f"using the first call only.",
            file=sys.stderr,
        )

    return tool_use_blocks[0]["input"], body


def compute_report_id(version, generated_at):
    return hashlib.sha256(f"{version}{generated_at}".encode("utf-8")).hexdigest()[:16]


def assemble_executive_report(ai_output, release_context):
    """Adds the Python-owned fields — see module docstring point 1. The
    model never sees or invents these."""
    release = release_context.get("release", {})
    generated_at = datetime.now(timezone.utc).isoformat()
    release_context_ref = {
        "repository": release.get("repository"),
        "version": release.get("version"),
        "generated_at": release.get("generated_at"),
    }
    report = {
        "schema_version": "1.0.0",
        "report_id": compute_report_id(release.get("version", ""), generated_at),
        "generated_at": generated_at,
        "release_context_ref": release_context_ref,
    }
    report.update(ai_output)
    return report


def verify_finding_id_references(report, real_finding_ids):
    """See module docstring point 3 — this exists because of a real,
    observed citation error, not a hypothetical one. Returns the list of
    invalid (location, finding_id) pairs found; does not raise — this is
    a warning-worthy data-quality signal, not a reason to discard an
    otherwise-valid report."""
    problems = []

    def walk(obj, path):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in FINDING_ID_PATTERN_FIELDS and isinstance(value, list):
                    for fid in value:
                        if fid not in real_finding_ids:
                            problems.append((path + "." + key, fid))
                else:
                    walk(value, path + "." + key)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{path}[{i}]")

    walk(report, "executive_report")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--release-context", required=True)
    parser.add_argument("--system-prompt", required=True)
    parser.add_argument("--schema", required=True)
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
    full_schema = load_json(args.schema)
    jsonschema.Draft202012Validator.check_schema(full_schema)  # the schema file itself must be valid

    release_context_text = load_text(args.release_context)
    try:
        release_context = json.loads(release_context_text)
    except json.JSONDecodeError as e:
        print(f"FATAL: {args.release_context} is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    real_finding_ids = {f.get("finding_id") for f in release_context.get("findings", []) if f.get("finding_id")}
    print(
        f"Analyzing {len(release_context.get('findings', []))} findings "
        f"({len(real_finding_ids)} distinct finding_ids) from {args.release_context} "
        f"(model: {args.model})..."
    )

    tool_schema = build_tool_schema(full_schema)
    ai_output, raw_response = call_claude(
        system_prompt, release_context_text, tool_schema, args.model, args.max_tokens, api_key
    )

    report = assemble_executive_report(ai_output, release_context)

    try:
        jsonschema.validate(report, full_schema)
    except jsonschema.ValidationError as e:
        print(
            f"FATAL: the assembled ExecutiveReport does not conform to "
            f"{args.schema}: {e.message} (at {'.'.join(str(p) for p in e.path)}). "
            f"Not writing a non-conformant artifact — this is a hard failure, not a "
            f"warning, since no renderer should be asked to consume an invalid contract.",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    usage = raw_response.get("usage", {})
    print(f"Wrote ExecutiveReport -> {args.output}")
    print(f"  report_id: {report['report_id']}")
    print(f"  recommendation: {report['release_readiness']['recommendation']}")
    print(f"  tokens: {usage.get('input_tokens', '?')} in / {usage.get('output_tokens', '?')} out")
    print(f"  stop_reason: {raw_response.get('stop_reason', '?')}")
    if raw_response.get("stop_reason") == "max_tokens":
        print(
            "  ::warning:: stopped at max_tokens — the tool call may have been truncated. "
            "Re-run with a higher --max-tokens.",
            file=sys.stderr,
        )

    # See module docstring point 3 and the function's own docstring for
    # exactly which real bug this check exists to catch.
    bad_refs = verify_finding_id_references(report, real_finding_ids)
    if bad_refs:
        print(
            f"  ::warning:: {len(bad_refs)} cited finding_id(s) do not exist in "
            f"{args.release_context}'s real findings — likely a transcription error citing "
            f"the same finding twice with slightly different ids:",
            file=sys.stderr,
        )
        for location, fid in bad_refs:
            print(f"    {location}: {fid!r}", file=sys.stderr)
    else:
        print(f"  All cited finding_id references verified against real findings.")


if __name__ == "__main__":
    main()