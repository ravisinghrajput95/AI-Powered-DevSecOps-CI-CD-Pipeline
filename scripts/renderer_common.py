#!/usr/bin/env python3
"""
Shared logic for any Renderer (Markdown, HTML, future PDF/Backstage).

Per the frozen three-layer separation, every renderer does the exact same
two deterministic resolution jobs against the exact same two input files
(ExecutiveReport.json + final_release_context.json) — only the output
format differs. This module is that shared logic, extracted out of
render_report.py rather than duplicated into render_html_report.py,
following the same Option A pattern (shared helpers, not copy-pasted
logic) already used throughout this pipeline's Python layer
(build_release_context.py's tag_findings/group_findings, etc.).

Two resolution jobs, both deterministic, neither requiring reasoning:
1. finding_id references in *_evidence arrays -> the real finding's
   rule_id/severity/category/message, looked up by finding_id.
2. assumptions_and_unknowns[].related_to pointers (e.g.
   "scan_status.backend.codeql") -> the actual value at that path. The
   AI only ever states the IMPACT of a gap; this is where the gap's
   actual value gets shown.

Also owns: loading both inputs, and validating the ExecutiveReport
against the schema before any renderer trusts it — confirmed necessary
by a real incident (see render_report.py's git history): a renderer
should never assume the producer already validated, since drift between
the schema and a renderer's own key-access code should surface as a
clear validation error here, not a confusing crash three functions deep.
"""
import json
import os
import sys

try:
    import jsonschema
except ImportError:
    print(
        "FATAL: the 'jsonschema' package is required (pip install jsonschema).",
        file=sys.stderr,
    )
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from executive_report_schema import SCHEMA


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def load_and_validate(executive_report_path, release_context_path):
    """The one entry point every renderer should call. Returns
    (report, release_context) or exits with a clear FATAL — never
    returns a report that hasn't been checked against SCHEMA."""
    report = load_json(executive_report_path)
    release_context = load_json(release_context_path)
    try:
        jsonschema.validate(report, SCHEMA)
    except jsonschema.ValidationError as e:
        print(
            f"FATAL: {executive_report_path} does not conform to executive_report_schema.SCHEMA: "
            f"{e.message} (at {'.'.join(str(p) for p in e.path)}). Refusing to "
            f"render a non-conformant artifact.",
            file=sys.stderr,
        )
        sys.exit(1)
    return report, release_context


def build_finding_lookup(release_context):
    return {f["finding_id"]: f for f in release_context.get("findings", []) if f.get("finding_id")}


def resolve_pointer(release_context, dotted_path):
    """Walks a dotted path like 'scan_status.backend.codeql' or
    'provenance.infrastructure_security' into final_release_context.json.
    Returns None if any segment doesn't resolve — the caller renders that
    as an explicit gap, not a crash."""
    node = release_context
    for segment in dotted_path.split("."):
        if isinstance(node, dict) and segment in node:
            node = node[segment]
        else:
            return None
    return node


RECOMMENDATION_LABELS = {
    "APPROVE": "Approve",
    "APPROVE_WITH_CONDITIONS": "Approve with conditions",
    "MANUAL_REVIEW_REQUIRED": "Manual review required",
    "DO_NOT_APPROVE": "Do not approve",
}