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

The tool's input_schema is DERIVED from executive_report_schema.SCHEMA at
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
   against executive_report_schema.SCHEMA. A schema violation is a hard
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
except ImportError as e:
    # raise, not print+sys.exit() — see renderer_common.py's identical
    # fix for why: this module gets imported by build_golden_executive_reports.py
    # (and potentially future tests), not only run standalone. SystemExit
    # during import crashes an importer's collection/load process instead
    # of surfacing as a normal, catchable error.
    raise ImportError(
        "the 'jsonschema' package is required (pip install jsonschema). "
        "Hand-rolling JSON Schema validation would reinvent a well-solved problem "
        "poorly — this is a deliberate dependency, not an oversight."
    ) from e

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from executive_report_schema import SCHEMA

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
    """Derive the tool's input_schema from executive_report_schema.SCHEMA —
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


def build_ai_projection(release_context):
    """Strips `locations` arrays from every finding before this gets sent
    to the model — measured at ~17% of total input tokens on a real
    46-finding sample, confirmed by actually computing it, not assumed.
    Zero reasoning-quality cost: the system prompt already forbids the
    model from citing anything but finding_id (see "Never duplicate a
    finding's content into your output"), so it architecturally never
    needs the raw location strings — only occurrence_count/total_locations
    (kept here) tell it whether a finding is widespread, which IS
    something its prioritization reasoning uses. The renderer resolves
    full location detail later, from the UNTRIMMED final_release_context.json
    — this projection only ever exists for the API call, never written to
    disk, never used for validation/finding_id-verification (those use
    the real, untrimmed release_context)."""
    import copy
    projection = copy.deepcopy(release_context)
    for f in projection.get("findings", []):
        f.pop("locations", None)
    return projection


def build_initial_messages(release_context_json):
    user_message = (
        "Analyze the following final_release_context.json and call "
        f"{TOOL_NAME} with your complete ExecutiveReport analysis, exactly "
        "as specified in your instructions.\n\n"
        "```json\n"
        f"{release_context_json}\n"
        "```"
    )
    return [{"role": "user", "content": user_message}]


def call_claude(messages, tool_schema, system_prompt, model, max_tokens, api_key, timeout):
    """One API call. Takes a full messages list, not just the initial
    user message — this is what makes the corrective retry in main()
    possible: a retry is just this same function called again with two
    more turns appended (the model's prior tool_use, and a tool_result
    telling it what was wrong), not a different code path."""
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": messages,
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
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        print(f"FATAL: Anthropic API returned HTTP {e.code}: {error_body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"FATAL: could not reach the Anthropic API: {e.reason}", file=sys.stderr)
        sys.exit(1)
    except TimeoutError:
        # Confirmed via a real run: a read timeout on an already-
        # established connection (the request was sent, the model was
        # generating, but the response didn't complete within `timeout`
        # seconds) raises a raw TimeoutError, NOT urllib.error.URLError —
        # it was propagating as an unhandled traceback rather than a
        # clean FATAL message. A 16384-max-tokens tool-use generation
        # over 54 findings can genuinely take a while; this is a timeout
        # value problem more than a code bug, but the crash-instead-of-
        # clean-failure was a real gap regardless of the right value.
        print(
            f"FATAL: the request to the Anthropic API timed out after {timeout}s waiting for "
            f"a response. The model may still have been generating — this is a read timeout, "
            f"not a connection failure. Re-run with a higher --timeout if this persists, "
            f"especially for large --max-tokens values.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Diagnostics printed HERE, unconditionally, for every attempt — not
    # only after a successful downstream validation. Confirmed via a real
    # run: the original code only logged stop_reason/token usage after
    # validation passed, so the first real validation failure gave no way
    # to tell whether it was caused by truncation (stop_reason: max_tokens)
    # or the model simply omitting a field within budget. Both are now
    # visible on every attempt, pass or fail.
    usage = body.get("usage", {})
    print(
        f"  [attempt] tokens: {usage.get('input_tokens', '?')} in / {usage.get('output_tokens', '?')} out, "
        f"stop_reason: {body.get('stop_reason', '?')}"
    )
    if body.get("stop_reason") == "max_tokens":
        print(
            "  ::warning:: stopped at max_tokens — the tool call may be truncated/incomplete. "
            "Consider raising --max-tokens.",
            file=sys.stderr,
        )

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

    block = tool_use_blocks[0]
    return block["input"], block["id"], body


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
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--model", default=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
        help="Defaults to claude-sonnet-4-6 (or $ANTHROPIC_MODEL) — a deliberate cost/quality "
             "tradeoff for a job that runs on every release; claude-opus-4-7 is the upgrade "
             "path if report quality, not cost, turns out to be the binding constraint.",
    )
    parser.add_argument(
        "--max-tokens", type=int, default=16384,
        help="Raised from an earlier default of 8192 after a real run with 54 findings — "
             "6 structured sections with evidence citations across that many findings can "
             "genuinely need more room. Now that every attempt logs its actual token usage "
             "(see call_claude), it'll be obvious from the logs if this still isn't enough.",
    )
    parser.add_argument(
        "--timeout", type=int, default=600,
        help="Raised from an earlier default of 180s after a real run hit a read timeout — "
             "a near-max-tokens tool-use generation over 54 findings can genuinely take "
             "longer than 3 minutes. This is a READ timeout (the request was sent, the model "
             "was generating, the response just didn't complete in time), not a connection "
             "failure — raising this is the correct fix, not a workaround for a bug.",
    )
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
    full_schema = SCHEMA
    jsonschema.Draft202012Validator.check_schema(full_schema)  # SCHEMA itself must be valid

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

    # See build_ai_projection's docstring — locations arrays stripped
    # before this goes to the model, never used for anything downstream
    # of the API call (validation/finding_id-verification/output all use
    # the original, untrimmed release_context).
    ai_projection_text = json.dumps(build_ai_projection(release_context))
    chars_saved = len(release_context_text) - len(ai_projection_text)
    print(f"  AI-facing context: {len(ai_projection_text)} chars (~{chars_saved // 4} fewer tokens than the full file, locations stripped)")

    tool_schema = build_tool_schema(full_schema)
    messages = build_initial_messages(ai_projection_text)

    # MAX_ATTEMPTS=2: one corrective retry, not an open-ended loop.
    # Confirmed via a real run that this is a real, recoverable failure
    # mode — the model called the tool but omitted a required field
    # (assumptions_and_unknowns) entirely. The correction is via a proper
    # tool_result with is_error: true, the API's actual documented
    # mechanism for "your tool call had a problem, fix it and call
    # again" — not an improvised follow-up user message.
    MAX_ATTEMPTS = 2
    report = None
    last_error = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"Calling the model (attempt {attempt}/{MAX_ATTEMPTS})...")
        ai_output, tool_use_id, raw_response = call_claude(
            messages, tool_schema, system_prompt, args.model, args.max_tokens, api_key, args.timeout
        )
        candidate_report = assemble_executive_report(ai_output, release_context)

        try:
            jsonschema.validate(candidate_report, full_schema)
            report = candidate_report
            break
        except jsonschema.ValidationError as e:
            last_error = e
            error_path = ".".join(str(p) for p in e.path) or "(top level)"
            print(
                f"  ::warning:: attempt {attempt} produced a non-conforming ExecutiveReport: "
                f"{e.message} (at {error_path})",
                file=sys.stderr,
            )
            if attempt < MAX_ATTEMPTS:
                messages.append({
                    "role": "assistant",
                    "content": [{"type": "tool_use", "id": tool_use_id, "name": TOOL_NAME, "input": ai_output}],
                })
                messages.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "is_error": True,
                        "content": (
                            f"Your {TOOL_NAME} call did not conform to the required schema: "
                            f"{e.message} (at {error_path}). Call {TOOL_NAME} again with the "
                            f"complete, corrected object — every required field populated."
                        ),
                    }],
                })

    if report is None:
        error_path = ".".join(str(p) for p in last_error.path) or "(top level)"
        print(
            f"FATAL: after {MAX_ATTEMPTS} attempts, the model never produced a schema-conforming "
            f"ExecutiveReport. Last error: {last_error.message} (at {error_path}). Not writing "
            f"a non-conformant artifact — this is a hard failure, not a warning, since no "
            f"renderer should be asked to consume an invalid contract.",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Wrote ExecutiveReport -> {args.output}")
    print(f"  report_id: {report['report_id']}")
    print(f"  recommendation: {report['release_readiness']['recommendation']}")

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
