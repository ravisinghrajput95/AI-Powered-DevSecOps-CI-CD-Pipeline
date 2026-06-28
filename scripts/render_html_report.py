#!/usr/bin/env python3
"""
The HTML Renderer. Same job as render_report.py (Markdown), same shared
resolution logic from renderer_common.py — only the output format
differs, per the frozen three-layer separation.

DESIGN INTENT, not incidental styling: this report is read by engineering
managers and security leads making a go/no-go call, not by SOC analysts
staring at a dashboard all day — so this deliberately isn't a dark
terminal/SIEM aesthetic. It's closer to a compliance audit document: a
light, authoritative body, with ONE dark element — a verdict banner up
top that separates THE DECISION from THE EVIDENCE, mirroring the
report's own architecture (AI recommendation vs. deterministic evidence
underneath it).

The signature element is the evidence chip: this entire pipeline's
defining principle is "evidence by reference, never duplicated" — every
claim cites a finding_id, never repeats finding content. In Markdown
that's inline text. Here it's a real interactive element — a <details>
disclosure (no JS required, fully keyboard-accessible by default) that
expands a bare finding_id into its resolved detail on demand. That's not
decoration; it's the report's own design philosophy made tangible.

SECURITY NOTE, worth being explicit about given what this script renders:
every text field in ExecutiveReport.json is model-generated content
being embedded into raw HTML. Every single one goes through html.escape()
before insertion — no exceptions, no "this field is probably fine."
Skipping that in a SECURITY report's own renderer would be a real, ironic
vulnerability, not a stylistic nicety.

Usage:
    render_html_report.py --executive-report executive_report.json \\
        --release-context final_release_context.json \\
        --output release_report.html
"""
import argparse
import html
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from renderer_common import load_and_validate, build_finding_lookup, resolve_pointer, RECOMMENDATION_LABELS

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def card_severity_class(finding_lookup, finding_ids):
    """Deterministic, not AI-driven: resolves the card's own cited
    evidence to find the highest severity among it, so the card itself
    carries a real signal — not just the small evidence chips. A
    cross-domain correlation citing one critical and one medium finding
    should read as critical at a glance, the same way a human scanning
    the report would weight it."""
    severities = [finding_lookup[fid]["severity"].lower() for fid in finding_ids if fid in finding_lookup and finding_lookup[fid].get("severity")]
    if not severities:
        return "informational"
    return min(severities, key=lambda s: SEVERITY_RANK.get(s, 99))


def esc(text):
    """The one rule that matters in this whole file: every piece of
    model-generated text goes through this before it touches the HTML
    string. See module docstring's SECURITY NOTE."""
    return html.escape(str(text), quote=True)


def confidence_badge(level):
    cls = level.lower()
    return f'<span class="badge badge-confidence badge-confidence--{esc(cls)}">{esc(level)} confidence</span>'


def evidence_chip(finding_lookup, finding_id):
    """The signature element — see module docstring. A native <details>
    disclosure, not JS: keyboard-accessible, works with no scripting,
    degrades to a plain expandable element if styling fails to load."""
    f = finding_lookup.get(finding_id)
    if f is None:
        return (
            f'<span class="chip chip--unresolved" title="Not found in final_release_context.json">'
            f'{esc(finding_id)} ⚠ unresolved</span>'
        )
    severity = (f.get("severity") or "unknown").lower()
    label = f.get("rule_id") or f.get("category") or finding_id
    message = f.get("sample_message") or ""
    category = f.get("category") or ""
    component = f.get("component") or ""
    return f"""<details class="chip chip--{esc(severity)}">
  <summary>{esc(finding_id)} <span class="chip-label">{esc(label)}</span></summary>
  <div class="chip-detail">
    <div class="chip-detail-row"><span class="chip-detail-key">severity</span> {esc(severity.upper())}</div>
    <div class="chip-detail-row"><span class="chip-detail-key">component</span> {esc(component)}</div>
    <div class="chip-detail-row"><span class="chip-detail-key">category</span> {esc(category)}</div>
    {f'<div class="chip-detail-row"><span class="chip-detail-key">message</span> {esc(message)}</div>' if message else ''}
  </div>
</details>"""


def evidence_row(finding_lookup, finding_ids, empty_label="No evidence cited"):
    if not finding_ids:
        return f'<p class="evidence-empty">{esc(empty_label)}</p>'
    chips = "\n".join(evidence_chip(finding_lookup, fid) for fid in finding_ids)
    return f'<div class="evidence-row">{chips}</div>'


def render_executive_summary(es):
    themes = "".join(f'<span class="theme-tag">{esc(t)}</span>' for t in es["dominant_risk_themes"])
    return f"""
<section id="executive-summary" class="block">
  <h2>Executive Summary</h2>
  <div class="summary-meta">
    <div class="summary-stat">
      <span class="summary-stat-label">Overall health</span>
      <span class="summary-stat-value health-{esc(es['overall_health'].lower())}">{esc(es['overall_health'])}</span>
    </div>
    <div class="summary-stat">
      <span class="summary-stat-label">Deployment confidence</span>
      <span class="summary-stat-value">{esc(es['deployment_confidence'])}</span>
    </div>
  </div>
  <div class="theme-tags">{themes}</div>
  <p class="narrative">{esc(es['narrative'])}</p>
</section>"""


def render_correlations(correlations, finding_lookup):
    if not correlations:
        return '<section id="cross-domain" class="block"><h2>Cross-Domain Analysis</h2><p class="empty-state">No cross-domain correlations identified this release.</p></section>'
    cards = []
    for c in correlations:
        domains = "".join(f'<span class="domain-tag">{esc(d.replace("_", " "))}</span>' for d in c["affected_domains"])
        sev = card_severity_class(finding_lookup, c["supporting_evidence"])
        cards.append(f"""
    <article class="card card--sev-{esc(sev)}">
      <div class="card-header">
        <h3>{esc(c['title'])}</h3>
        {confidence_badge(c['confidence'])}
      </div>
      <div class="domain-tags">{domains}</div>
      <p>{esc(c['description'])}</p>
      <p class="impact-line"><strong>Business impact:</strong> {esc(c['business_impact'])}</p>
      <p class="action-line"><strong>Recommended action:</strong> {esc(c['recommended_action'])}</p>
      {evidence_row(finding_lookup, c['supporting_evidence'])}
    </article>""")
    return f'<section id="cross-domain" class="block"><h2>Cross-Domain Analysis</h2>{"".join(cards)}</section>'


def render_top_risks(risks, finding_lookup):
    if not risks:
        return '<section id="top-risks" class="block"><h2>Top Risks</h2><p class="empty-state">No risks identified this release.</p></section>'
    cards = []
    for i, r in enumerate(risks, start=1):
        sev = card_severity_class(finding_lookup, r["supporting_evidence"])
        cards.append(f"""
    <article class="card card--sev-{esc(sev)}">
      <div class="card-header">
        <h3><span class="rank">{i}</span> {esc(r['title'])}</h3>
        {confidence_badge(r['confidence'])}
      </div>
      <p>{esc(r['impact'])}</p>
      <p class="impact-line"><strong>Why it matters:</strong> {esc(r['why_it_matters'])}</p>
      <p class="action-line"><strong>Recommended action:</strong> {esc(r['recommended_action'])}</p>
      {evidence_row(finding_lookup, r['supporting_evidence'])}
    </article>""")
    return f'<section id="top-risks" class="block"><h2>Top Risks</h2>{"".join(cards)}</section>'


def render_priority_actions(actions, finding_lookup):
    if not actions:
        return '<section id="priority-actions" class="block"><h2>Highest Priority Actions</h2><p class="empty-state">No priority actions identified this release.</p></section>'
    cards = []
    for i, a in enumerate(actions, start=1):
        deps = ", ".join(a["dependencies"]) if a["dependencies"] else "none"
        evidence = evidence_row(finding_lookup, a["supporting_evidence"], empty_label="") if a["supporting_evidence"] else ""
        cards.append(f"""
    <article class="card card--action">
      <div class="card-header">
        <h3><span class="rank">{i}</span> {esc(a['title'])}</h3>
        <span class="badge badge-complexity badge-complexity--{esc(a['estimated_complexity'].lower())}">{esc(a['estimated_complexity'])} complexity</span>
      </div>
      <p>{esc(a['rationale'])}</p>
      <p class="impact-line"><strong>Expected risk reduction:</strong> {esc(a['expected_risk_reduction'])}</p>
      <p class="deps-line"><strong>Dependencies:</strong> {esc(deps)}</p>
      {evidence}
    </article>""")
    return f'<section id="priority-actions" class="block"><h2>Highest Priority Actions</h2>{"".join(cards)}</section>'


def render_assumptions(assumptions, release_context):
    if not assumptions:
        return '<section id="assumptions" class="block"><h2>Assumptions &amp; Unknowns</h2><p class="empty-state">No gaps or unknowns flagged this release.</p></section>'
    rows = []
    for a in assumptions:
        resolved = resolve_pointer(release_context, a["related_to"])
        resolved_str = "pointer did not resolve" if resolved is None else json.dumps(resolved)
        rows.append(f"""
    <div class="assumption-row">
      <div class="assumption-pointer">{esc(a['related_to'])}</div>
      <div class="assumption-value">{esc(resolved_str)}</div>
      <div class="assumption-impact">{esc(a['impact_on_assessment'])}</div>
    </div>""")
    return f'<section id="assumptions" class="block"><h2>Assumptions &amp; Unknowns</h2><div class="assumptions-table">{"".join(rows)}</div></section>'


def render_release_readiness(rr, finding_lookup):
    conditions = ""
    if rr["conditions"]:
        items = "".join(f"<li>{esc(c)}</li>" for c in rr["conditions"])
        conditions = f'<div class="conditions"><strong>Conditions:</strong><ul>{items}</ul></div>'
    sev = card_severity_class(finding_lookup, rr["blocking_evidence"])
    return f"""
<section id="release-readiness" class="block">
  <h2>Release Readiness Assessment</h2>
  <div class="card card--sev-{esc(sev)}">
    {confidence_badge(rr['confidence'])}
    <p>{esc(rr['rationale'])}</p>
    {conditions}
    <p class="evidence-label"><strong>Blocking evidence</strong></p>
    {evidence_row(finding_lookup, rr['blocking_evidence'], empty_label="No blocking evidence cited")}
  </div>
</section>"""


def render_verdict_banner(report, release_context):
    rr = report["release_readiness"]
    ref = report["release_context_ref"]
    rec = rr["recommendation"]
    components = ", ".join(release_context.get("release", {}).get("components", []))
    return f"""
<header class="verdict">
  <div class="verdict-inner">
    <div class="verdict-main">
      <span class="verdict-label">Final recommendation</span>
      <h1 class="verdict-rec verdict-rec--{esc(rec.lower())}">{esc(RECOMMENDATION_LABELS[rec])}</h1>
    </div>
    <dl class="verdict-meta">
      <div><dt>Repository</dt><dd class="mono">{esc(ref['repository'])}</dd></div>
      <div><dt>Commit</dt><dd class="mono">{esc(ref['version'][:12])}</dd></div>
      <div><dt>Components</dt><dd>{esc(components)}</dd></div>
      <div><dt>Report ID</dt><dd class="mono">{esc(report['report_id'])}</dd></div>
      <div><dt>Generated</dt><dd>{esc(report['generated_at'])}</dd></div>
    </dl>
  </div>
</header>"""


TOC_ITEMS = [
    ("executive-summary", "Executive Summary"),
    ("cross-domain", "Cross-Domain Analysis"),
    ("top-risks", "Top Risks"),
    ("priority-actions", "Priority Actions"),
    ("release-readiness", "Release Readiness"),
    ("assumptions", "Assumptions & Unknowns"),
    ("final-recommendation", "Final Recommendation"),
]


def render_toc():
    items = "".join(f'<li><a href="#{i}">{esc(label)}</a></li>' for i, label in TOC_ITEMS)
    return f'<nav class="toc" aria-label="Report sections"><ul>{items}</ul></nav>'


CSS = """
:root {
  --bg: #F7F8FA;
  --surface: #FFFFFF;
  --border: #E3E6EB;
  --text: #1A1D23;
  --text-muted: #5B6270;
  --banner-bg: #12161F;
  --banner-text: #F0F2F5;
  --banner-text-muted: #9BA3B0;
  --accent: #0F6B66;
  --accent-soft: #E3F1EF;
  --sev-critical: #A6233D;
  --sev-high: #B5541E;
  --sev-medium: #9C7A0C;
  --sev-low: #3C6E91;
  --sev-informational: #6B7280;
  --radius: 10px;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
  *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
}
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: 'IBM Plex Sans', -apple-system, sans-serif;
  font-size: 16px;
  line-height: 1.6;
}
.mono { font-family: 'IBM Plex Mono', monospace; font-size: 0.92em; }
h1, h2, h3 { font-family: 'Fraunces', serif; font-weight: 600; line-height: 1.2; margin: 0; }
a { color: var(--accent); }
a:focus-visible, summary:focus-visible, button:focus-visible {
  outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px;
}

/* Verdict banner */
.verdict { background: var(--banner-bg); color: var(--banner-text); padding: 48px 24px; }
.verdict-inner { max-width: 1100px; margin: 0 auto; display: flex; flex-wrap: wrap; gap: 32px; justify-content: space-between; align-items: flex-end; }
.verdict-label { display: block; font-size: 0.8rem; letter-spacing: 0.08em; text-transform: uppercase; color: var(--banner-text-muted); margin-bottom: 8px; }
.verdict-rec { font-size: clamp(1.8rem, 4vw, 3rem); margin: 0; }
.verdict-rec--approve { color: #6FCF97; }
.verdict-rec--approve_with_conditions { color: #F2C94C; }
.verdict-rec--manual_review_required { color: #56CCF2; }
.verdict-rec--do_not_approve { color: #EB5757; }
.verdict-meta { display: grid; grid-template-columns: repeat(2, auto); gap: 12px 32px; margin: 0; font-size: 0.88rem; }
.verdict-meta dt { color: var(--banner-text-muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
.verdict-meta dd { margin: 2px 0 0; }

/* Layout */
.layout { max-width: 1100px; margin: 0 auto; display: grid; grid-template-columns: 220px 1fr; gap: 40px; padding: 32px 24px 80px; }
.toc { position: sticky; top: 24px; align-self: start; }
.toc ul { list-style: none; padding: 0; margin: 0; border-left: 2px solid var(--border); }
.toc li a { display: block; padding: 6px 16px; color: var(--text-muted); text-decoration: none; font-size: 0.9rem; }
.toc li a:hover { color: var(--accent); }
.document { min-width: 0; }
.block { margin-bottom: 56px; }
.block h2 { font-size: 1.5rem; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 1px solid var(--border); }
.empty-state { color: var(--text-muted); font-style: italic; }

/* Executive summary */
.summary-meta { display: flex; gap: 32px; margin-bottom: 20px; }
.summary-stat { display: flex; flex-direction: column; }
.summary-stat-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }
.summary-stat-value { font-family: 'Fraunces', serif; font-size: 1.4rem; font-weight: 600; }
.health-critical { color: var(--sev-critical); }
.health-high { color: var(--sev-high); }
.health-medium { color: var(--sev-medium); }
.health-low { color: var(--sev-low); }
.theme-tags { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
.theme-tag { background: var(--accent-soft); color: var(--accent); padding: 4px 12px; border-radius: 100px; font-size: 0.85rem; }
.narrative { font-size: 1.05rem; }

/* Cards */
.card { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--sev-informational); border-radius: var(--radius); padding: 24px; margin-bottom: 16px; }
.card--sev-critical { border-left-color: var(--sev-critical); }
.card--sev-high { border-left-color: var(--sev-high); }
.card--sev-medium { border-left-color: var(--sev-medium); }
.card--sev-low { border-left-color: var(--sev-low); }
.card--action { border-left-color: var(--accent); }
.card-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 12px; }
.card-header h3 { font-size: 1.15rem; flex: 1; }
.rank { display: inline-flex; align-items: center; justify-content: center; width: 24px; height: 24px; background: var(--banner-bg); color: var(--surface); border-radius: 50%; font-family: 'IBM Plex Sans', sans-serif; font-size: 0.8rem; font-weight: 600; margin-right: 8px; }
.card p { margin: 8px 0; }
.impact-line, .action-line, .deps-line { font-size: 0.95rem; color: var(--text-muted); }
.impact-line strong, .action-line strong, .deps-line strong { color: var(--text); }
.domain-tags { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; }
.domain-tag { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.03em; background: var(--bg); border: 1px solid var(--border); padding: 2px 8px; border-radius: 4px; color: var(--text-muted); }

/* Badges — confidence deliberately uses a neutral grey/blue scale, NOT
   green-for-high: a HIGH-confidence CRITICAL risk needs the badge to
   read as "certain," not "good news" — green specifically reads as
   positive/safe, which would semantically clash with bad news stated
   confidently. Complexity badges keep green/amber/red since LOW
   complexity genuinely IS the favorable case there. */
.badge { font-size: 0.75rem; padding: 4px 10px; border-radius: 100px; white-space: nowrap; font-weight: 500; }
.badge-confidence--high { background: #E2E8F0; color: #334155; }
.badge-confidence--medium { background: #EDF1F5; color: #5B6477; }
.badge-confidence--low { background: #F1F2F4; color: var(--text-muted); }
.badge-complexity--low { background: #E4F2E9; color: #237042; }
.badge-complexity--medium { background: #FCF3DC; color: #8A6A06; }
.badge-complexity--high { background: #FAE3E3; color: #A6233D; }
.badge-complexity--unknown { background: #F1F2F4; color: var(--text-muted); }

/* Evidence chips - the signature element */
.evidence-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.evidence-empty { color: var(--text-muted); font-size: 0.9rem; font-style: italic; margin-top: 8px; }
.evidence-label { margin-top: 16px; margin-bottom: 0; font-size: 0.85rem; }
.chip { display: inline-block; }
.chip summary {
  list-style: none; cursor: pointer; font-family: 'IBM Plex Mono', monospace; font-size: 0.78rem;
  background: var(--bg); border: 1px solid var(--border); border-left: 3px solid var(--sev-informational);
  border-radius: 6px; padding: 4px 10px; display: flex; align-items: center; gap: 6px;
}
.chip summary::-webkit-details-marker { display: none; }
.chip summary:hover { border-color: var(--accent); }
.chip-label { font-family: 'IBM Plex Sans', sans-serif; color: var(--text-muted); }
.chip--critical summary { border-left-color: var(--sev-critical); }
.chip--high summary { border-left-color: var(--sev-high); }
.chip--medium summary { border-left-color: var(--sev-medium); }
.chip--low summary { border-left-color: var(--sev-low); }
.chip--informational summary { border-left-color: var(--sev-informational); }
.chip--unresolved { font-family: 'IBM Plex Mono', monospace; font-size: 0.78rem; background: #FAE3E3; color: var(--sev-critical); border-radius: 6px; padding: 4px 10px; }
.chip-detail { background: var(--surface); border: 1px solid var(--border); border-top: none; border-radius: 0 0 6px 6px; padding: 10px 12px; font-size: 0.82rem; margin-top: -1px; }
.chip-detail-row { display: flex; gap: 8px; padding: 2px 0; }
.chip-detail-key { font-family: 'IBM Plex Mono', monospace; color: var(--text-muted); min-width: 70px; flex-shrink: 0; }

/* Assumptions table */
.assumptions-table { display: flex; flex-direction: column; gap: 1px; background: var(--border); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
.assumption-row { display: grid; grid-template-columns: 1fr 1fr 2fr; gap: 16px; background: var(--surface); padding: 14px 16px; }
.assumption-pointer { font-family: 'IBM Plex Mono', monospace; font-size: 0.8rem; color: var(--accent); }
.assumption-value { font-family: 'IBM Plex Mono', monospace; font-size: 0.8rem; color: var(--text-muted); word-break: break-word; }
.assumption-impact { font-size: 0.9rem; }
.conditions { margin: 12px 0; font-size: 0.95rem; }
.conditions ul { margin: 8px 0 0; padding-left: 20px; }

/* Closing recommendation recap */
.closing-rec { border-radius: var(--radius); padding: 24px; border: 2px solid; }
.closing-rec-label { font-family: 'Fraunces', serif; font-size: 1.3rem; font-weight: 600; display: block; margin-bottom: 8px; }
.closing-rec p { margin: 0; color: var(--text-muted); }
.closing-rec--approve { border-color: #6FCF97; background: #F0FAF4; }
.closing-rec--approve .closing-rec-label { color: #237042; }
.closing-rec--approve_with_conditions { border-color: #F2C94C; background: #FDF8EC; }
.closing-rec--approve_with_conditions .closing-rec-label { color: #8A6A06; }
.closing-rec--manual_review_required { border-color: #56CCF2; background: #EEFAFD; }
.closing-rec--manual_review_required .closing-rec-label { color: #1A6E8A; }
.closing-rec--do_not_approve { border-color: #EB5757; background: #FDEEEE; }
.closing-rec--do_not_approve .closing-rec-label { color: var(--sev-critical); }

@media (max-width: 800px) {
  .layout { grid-template-columns: 1fr; }
  .toc { position: static; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 8px; }
  .toc ul { border-left: none; display: flex; flex-wrap: wrap; gap: 4px; }
  .toc li a { padding: 6px 10px; }
  .verdict-meta { grid-template-columns: 1fr; }
  .assumption-row { grid-template-columns: 1fr; gap: 4px; }
}
"""


def render_closing_recommendation(rr):
    """A closing recap of the verdict, mirroring the Markdown renderer's
    structure — added after noticing a real UX gap: on a long document
    (16,000+ px in a real run), the recommendation only appearing once in
    the top banner means a reader who scrolls through everything has lost
    sight of it by the time they reach Assumptions. Simpler fix than a
    sticky/shrinking header (which would need JS to do well) — just state
    it again, clearly, at the end."""
    return f"""
<section id="final-recommendation" class="block">
  <h2>Final Recommendation</h2>
  <div class="closing-rec closing-rec--{esc(rr['recommendation'].lower())}">
    <span class="closing-rec-label">{esc(RECOMMENDATION_LABELS[rr['recommendation']])}</span>
    <p>{esc(rr['rationale'])}</p>
  </div>
</section>"""


def render_html(report, release_context):
    finding_lookup = build_finding_lookup(release_context)
    ref = report["release_context_ref"]
    title = f"Release Intelligence Report — {esc(ref['repository'])}"

    body = "\n".join([
        render_verdict_banner(report, release_context),
        '<div class="layout">',
        render_toc(),
        '<main class="document">',
        render_executive_summary(report["executive_summary"]),
        render_correlations(report["cross_domain_correlations"], finding_lookup),
        render_top_risks(report["top_risks"], finding_lookup),
        render_priority_actions(report["priority_actions"], finding_lookup),
        render_release_readiness(report["release_readiness"], finding_lookup),
        render_assumptions(report["assumptions_and_unknowns"], release_context),
        render_closing_recommendation(report["release_readiness"]),
        '</main>',
        '</div>',
    ])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500;9..144,600;9..144,700&family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>{CSS}</style>
</head>
<body>
{body}
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--executive-report", required=True)
    parser.add_argument("--release-context", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    report, release_context = load_and_validate(args.executive_report, args.release_context)
    html_doc = render_html(report, release_context)

    with open(args.output, "w") as f:
        f.write(html_doc)

    # "⚠ unresolved" (not "chip--unresolved") — the class name also
    # appears once in the CSS definition itself regardless of whether any
    # real unresolved chip exists, which was producing a false-positive
    # warning on every single render. Confirmed by checking a real run's
    # output directly: count("chip--unresolved") == 1 even with zero
    # actual unresolved references present.
    unresolved = html_doc.count("⚠ unresolved")
    print(f"Rendered {args.executive_report} -> {args.output} ({len(html_doc)} chars)")
    if unresolved:
        print(
            f"::warning:: {unresolved} unresolved finding_id reference(s) in the rendered output.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
