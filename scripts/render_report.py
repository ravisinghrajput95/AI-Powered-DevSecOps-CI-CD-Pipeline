#!/usr/bin/env python3
"""
The Markdown Renderer. Takes ExecutiveReport.json (AI reasoning, no
presentation markup) + final_release_context.json (the evidence it
references by finding_id) and produces release_report.md.

This is a genuinely separate component, not just a conceptually-separate
section of run_security_analysis.py — per the frozen three-layer
separation, the AI never touches Markdown, and this script never touches
the model.

Shared resolution logic (finding_id lookup, related_to pointer
resolution, schema validation) lives in renderer_common.py — the HTML
renderer (render_html_report.py) uses the exact same logic, only the
output format differs. See renderer_common.py's docstring for why this
is shared rather than duplicated.

A finding_id that doesn't resolve (the exact failure mode
run_security_analysis.py's verify_finding_id_references() checks for) is
rendered with an explicit "[unresolved reference]" marker rather than
silently dropped or causing a crash — a broken citation should be visibly
broken, not invisible.

Usage:
    render_report.py --executive-report executive_report.json \\
        --release-context final_release_context.json \\
        --output release_report.md
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from renderer_common import load_and_validate, build_finding_lookup, resolve_pointer, RECOMMENDATION_LABELS


def cite(finding_lookup, finding_id):
    """Renders one evidence reference as a short, human-readable
    citation. This is the ONLY place finding detail gets displayed —
    ExecutiveReport.json itself never carries it."""
    f = finding_lookup.get(finding_id)
    if f is None:
        return f"`{finding_id}` [unresolved reference — not found in final_release_context.json]"
    label = f.get("rule_id") or f.get("category") or finding_id
    severity = (f.get("severity") or "unknown").upper()
    return f"`{finding_id}` ({label}, {severity})"


def cite_list(finding_lookup, finding_ids):
    if not finding_ids:
        return "_none cited_"
    return "; ".join(cite(finding_lookup, fid) for fid in finding_ids)


def render_executive_summary(es):
    lines = ["## Executive Summary", ""]
    lines.append(f"**Overall Health:** {es['overall_health']} &nbsp;|&nbsp; **Deployment Confidence:** {es['deployment_confidence']}")
    lines.append("")
    lines.append("**Dominant Risk Themes:** " + ", ".join(es["dominant_risk_themes"]))
    lines.append("")
    lines.append(es["narrative"])
    lines.append("")
    return lines


def render_correlations(correlations, finding_lookup):
    lines = ["## Cross-Domain Analysis", ""]
    if not correlations:
        lines.append("_No cross-domain correlations identified this release._")
        lines.append("")
        return lines
    for c in correlations:
        lines.append(f"### {c['title']}")
        lines.append("")
        lines.append(f"**Affected domains:** {', '.join(c['affected_domains'])} &nbsp;|&nbsp; **Confidence:** {c['confidence']}")
        lines.append("")
        lines.append(c["description"])
        lines.append("")
        lines.append(f"**Business impact:** {c['business_impact']}")
        lines.append("")
        lines.append(f"**Recommended action:** {c['recommended_action']}")
        lines.append("")
        lines.append(f"**Evidence:** {cite_list(finding_lookup, c['supporting_evidence'])}")
        lines.append("")
    return lines


def render_top_risks(risks, finding_lookup):
    lines = ["## Top Risks", ""]
    if not risks:
        lines.append("_No risks identified this release._")
        lines.append("")
        return lines
    for i, r in enumerate(risks, start=1):
        lines.append(f"### Risk {i}: {r['title']}")
        lines.append("")
        lines.append(f"**Confidence:** {r['confidence']}")
        lines.append("")
        lines.append(f"**Impact:** {r['impact']}")
        lines.append("")
        lines.append(f"**Why it matters:** {r['why_it_matters']}")
        lines.append("")
        lines.append(f"**Recommended action:** {r['recommended_action']}")
        lines.append("")
        lines.append(f"**Evidence:** {cite_list(finding_lookup, r['supporting_evidence'])}")
        lines.append("")
    return lines


def render_priority_actions(actions, finding_lookup):
    lines = ["## Highest Priority Actions", ""]
    if not actions:
        lines.append("_No priority actions identified this release._")
        lines.append("")
        return lines
    for i, a in enumerate(actions, start=1):
        deps = ", ".join(a["dependencies"]) if a["dependencies"] else "none"
        lines.append(f"### Action {i}: {a['title']}")
        lines.append("")
        lines.append(f"**Estimated complexity:** {a['estimated_complexity']} &nbsp;|&nbsp; **Dependencies:** {deps}")
        lines.append("")
        lines.append(a["rationale"])
        lines.append("")
        lines.append(f"**Expected risk reduction:** {a['expected_risk_reduction']}")
        lines.append("")
        if a["supporting_evidence"]:
            lines.append(f"**Evidence:** {cite_list(finding_lookup, a['supporting_evidence'])}")
            lines.append("")
    return lines


def render_release_readiness(rr, finding_lookup):
    lines = ["## Release Readiness Assessment", ""]
    lines.append(f"**Confidence:** {rr['confidence']}")
    lines.append("")
    lines.append(rr["rationale"])
    lines.append("")
    lines.append(f"**Blocking evidence:** {cite_list(finding_lookup, rr['blocking_evidence'])}")
    lines.append("")
    if rr["conditions"]:
        lines.append("**Conditions:**")
        for cond in rr["conditions"]:
            lines.append(f"- {cond}")
        lines.append("")
    return lines


def render_assumptions(assumptions, release_context):
    lines = ["## Assumptions & Unknowns", ""]
    if not assumptions:
        lines.append("_No gaps or unknowns flagged this release._")
        lines.append("")
        return lines
    for a in assumptions:
        resolved = resolve_pointer(release_context, a["related_to"])
        if resolved is None:
            resolved_str = "_[pointer did not resolve against final_release_context.json]_"
        else:
            resolved_str = f"`{json.dumps(resolved)}`"
        lines.append(f"- **`{a['related_to']}`** = {resolved_str} — {a['impact_on_assessment']}")
    lines.append("")
    return lines


def render_final_recommendation(rr):
    lines = ["## Final Recommendation", ""]
    icon = {"APPROVE": "✅", "APPROVE_WITH_CONDITIONS": "⚠️", "MANUAL_REVIEW_REQUIRED": "🔍", "DO_NOT_APPROVE": "❌"}[rr["recommendation"]]
    lines.append(f"### {icon} {RECOMMENDATION_LABELS[rr['recommendation']].upper()}")
    lines.append("")
    lines.append(rr["rationale"])
    lines.append("")
    return lines


def render_markdown(report, release_context):
    finding_lookup = build_finding_lookup(release_context)
    ref = report["release_context_ref"]

    lines = [
        "# Release Intelligence Report",
        "",
        f"**Repository:** `{ref['repository']}`",
        f"**Release Version:** `{ref['version']}`",
        f"**Report Generated:** {report['generated_at']}",
        f"**Report ID:** `{report['report_id']}`",
        f"**Components Assessed:** {', '.join(release_context.get('release', {}).get('components', []))}",
        "",
        "---",
        "",
    ]
    lines += render_executive_summary(report["executive_summary"])
    lines += ["---", ""]
    lines += render_correlations(report["cross_domain_correlations"], finding_lookup)
    lines += ["---", ""]
    lines += render_top_risks(report["top_risks"], finding_lookup)
    lines += ["---", ""]
    lines += render_priority_actions(report["priority_actions"], finding_lookup)
    lines += ["---", ""]
    lines += render_release_readiness(report["release_readiness"], finding_lookup)
    lines += ["---", ""]
    lines += render_assumptions(report["assumptions_and_unknowns"], release_context)
    lines += ["---", ""]
    lines += render_final_recommendation(report["release_readiness"])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--executive-report", required=True)
    parser.add_argument("--release-context", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    report, release_context = load_and_validate(args.executive_report, args.release_context)
    markdown = render_markdown(report, release_context)

    with open(args.output, "w") as f:
        f.write(markdown)

    unresolved = markdown.count("[unresolved reference")
    print(f"Rendered {args.executive_report} -> {args.output} ({len(markdown)} chars)")
    if unresolved:
        print(
            f"::warning:: {unresolved} unresolved finding_id reference(s) in the rendered output "
            f"— see run_security_analysis.py's finding_id verification warnings for which ones.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()