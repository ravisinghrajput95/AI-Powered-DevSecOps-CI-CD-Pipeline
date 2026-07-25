#!/usr/bin/env python3
"""Append-only record of what each real AI run actually produced.

Everything else in tests/ measures the deterministic half of this pipeline.
Nothing measures whether the model gives the same answer twice — and that is
the first question anyone sensible asks about an LLM in a release gate.

The expensive way to answer it is an evaluation harness: hand-authored
expected correlations per fixture, a scoring function, and N commissioned runs
per measurement. That was considered and rejected. Labelling ground truth for
nine fixtures is days of judgement work needing maintenance whenever fixtures
change, to grade a system whose *verdict* turns out to be the stable part.

This is the cheap tenth of it that carries most of the value: you are already
paying for real runs, so record what each one produced. The stability table
builds itself over time at no additional cost.

WHAT THIS DOES AND DOES NOT CLAIM

Variance is only meaningful between runs over identical evidence. Runs at
different commits legitimately differ — different findings, different
provenance — so `summary` groups by release version and reports within-group
stability separately from cross-group spread. Reading a cross-commit
difference as model noise would be exactly the kind of overstatement this
pipeline exists to avoid.

The model identifier is passed in rather than read from the report, because
ExecutiveReport v1.0 does not record which model produced it. That is a real
gap in an artifact meant to be auditable, but the schema is frozen and
unfreezing it is a deliberate decision, not something to slip into a
reporting utility. Until then the caller supplies it; release-readiness.yaml
passes $ANTHROPIC_MODEL, the same value it hands the engine.

Correlation titles are model-authored prose, so they never match literally
between runs. `THEME_KEYWORDS` reduces them to coarse recurring themes. It is
a documented heuristic, not a semantic model: a theme appearing in every run
is strong evidence of stability, while a one-off may be a genuine difference
or merely different wording. Raw titles are kept in every row so the mapping
can be revisited without re-running anything.

Usage:
    run_ledger.py record --executive-report executive_report.json \\
        --release-context final_release_context.json \\
        --model claude-sonnet-4-6
    run_ledger.py summary
"""

import argparse
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_LEDGER = os.path.join(ROOT, "reports", "run_ledger.jsonl")

# Ordered: the first match wins, so put specific terms before general ones.
THEME_KEYWORDS = [
    ("workload identity", "workload-identity+iam"),
    ("metadata server", "workload-identity+iam"),
    ("iam", "workload-identity+iam"),
    ("unsigned", "unsigned-images"),
    ("signature", "unsigned-images"),
    ("provenance", "unsigned-images"),
    ("verif", "unsigned-images"),
    ("secret", "hardcoded-secrets"),
    ("credential", "hardcoded-secrets"),
    ("injection", "injection"),
    ("traversal", "injection"),
    ("firewall", "open-network"),
    ("network", "open-network"),
    ("privilege", "privilege-escalation"),
    ("escalation", "privilege-escalation"),
    ("root", "privilege-escalation"),
    ("cve", "container-cves"),
    ("os-layer", "container-cves"),
    ("dependenc", "dependencies"),
    ("outdated", "dependencies"),
    ("xss", "xss"),
]


def theme_of(title):
    """Coarse theme for a model-authored correlation title. See module docstring."""
    lowered = title.lower()
    for needle, theme in THEME_KEYWORDS:
        if needle in lowered:
            return theme
    return "other:" + lowered[:24].strip()


def build_row(report, context, model):
    """One ledger row. Only fields that are cheap, stable and comparable."""
    summary = report.get("executive_summary", {})
    readiness = report.get("release_readiness", {})
    correlations = report.get("cross_domain_correlations", [])

    scan_status = context.get("scan_status", {})
    statuses = [
        v for tools in scan_status.values() if isinstance(tools, dict) for v in tools.values()
    ]

    return {
        "report_id": report.get("report_id"),
        "generated_at": report.get("generated_at"),
        "release_version": (report.get("release_context_ref") or {}).get("version"),
        "model": model,
        "recommendation": readiness.get("recommendation"),
        "readiness_confidence": readiness.get("confidence"),
        "overall_health": summary.get("overall_health"),
        "deployment_confidence": summary.get("deployment_confidence"),
        "n_findings": len(context.get("findings", [])),
        "n_correlations": len(correlations),
        "n_top_risks": len(report.get("top_risks", [])),
        "n_assumptions": len(report.get("assumptions_and_unknowns", [])),
        "n_blocking_evidence": len(readiness.get("blocking_evidence") or []),
        "scanners_total": len(statuses),
        "scanners_success": sum(1 for s in statuses if s == "SUCCESS"),
        "correlation_themes": sorted({theme_of(c.get("title", "")) for c in correlations}),
        "correlation_titles": [c.get("title", "") for c in correlations],
    }


def load_ledger(path):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def cmd_record(args):
    with open(args.executive_report, encoding="utf-8") as f:
        report = json.load(f)
    with open(args.release_context, encoding="utf-8") as f:
        context = json.load(f)

    row = build_row(report, context, args.model)

    existing = load_ledger(args.ledger)
    if any(r.get("report_id") == row["report_id"] for r in existing):
        print(f"Report {row['report_id']} is already in the ledger — nothing appended.")
        return 0

    os.makedirs(os.path.dirname(args.ledger), exist_ok=True)
    with open(args.ledger, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")
    print(f"Recorded {row['report_id']} ({row['recommendation']}, "
          f"{row['n_correlations']} correlations) -> {os.path.relpath(args.ledger, ROOT)}")
    return 0


def cmd_summary(args):
    rows = load_ledger(args.ledger)
    if not rows:
        print("Ledger is empty. Record a run first.")
        return 0

    print(f"{len(rows)} recorded run(s)\n")
    header = f"  {'report':<10} {'release':<10} {'model':<20} {'verdict':<18} {'corr':>4} {'risks':>5} {'scan':>7}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for r in rows:
        scan = f"{r.get('scanners_success', 0)}/{r.get('scanners_total', 0)}"
        print(f"  {str(r.get('report_id'))[:8]:<10} {str(r.get('release_version'))[:8]:<10} "
              f"{str(r.get('model'))[:20]:<20} {str(r.get('recommendation')):<18} "
              f"{r.get('n_correlations', 0):>4} {r.get('n_top_risks', 0):>5} {scan:>7}")

    # Verdict stability is the number that matters: it is what gates a deploy.
    verdicts = collections.Counter(r.get("recommendation") for r in rows)
    print(f"\n  Verdict across all runs: " + ", ".join(f"{v} x{c}" for v, c in verdicts.most_common()))
    if len(verdicts) == 1:
        print("    -> identical in every recorded run")
    else:
        print("    -> DIFFERS between runs; check whether the evidence differed too")

    # Theme recurrence, reported per release version so cross-commit
    # differences are never presented as model variance.
    by_release = collections.defaultdict(list)
    for r in rows:
        by_release[r.get("release_version")].append(r)

    comparable = {k: v for k, v in by_release.items() if len(v) > 1}
    if comparable:
        print("\n  Correlation-theme stability over IDENTICAL evidence:")
        for release, group in comparable.items():
            counts = collections.Counter(t for r in group for t in r.get("correlation_themes", []))
            n = len(group)
            core = [t for t, c in counts.items() if c == n]
            print(f"    {str(release)[:8]} ({n} runs): {len(core)}/{len(counts)} themes in every run")
            for t, c in counts.most_common():
                print(f"      {c}/{n}  {t}")
    else:
        print("\n  No release version has more than one run yet, so within-evidence")
        print("  variance cannot be measured. The spread below is ACROSS different")
        print("  commits and different evidence — it is not model noise.")

    counts = collections.Counter(t for r in rows for t in r.get("correlation_themes", []))
    n = len(rows)
    core = sorted(t for t, c in counts.items() if c == n)
    print(f"\n  Themes present in all {n} recorded run(s): {len(core)}/{len(counts)}")
    for t in core:
        print(f"    {t}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    rec = sub.add_parser("record", help="append one run to the ledger")
    rec.add_argument("--executive-report", required=True)
    rec.add_argument("--release-context", required=True)
    rec.add_argument("--model", required=True,
                     help="ExecutiveReport v1.0 does not record this; pass the model used.")
    rec.add_argument("--ledger", default=DEFAULT_LEDGER)
    rec.set_defaults(func=cmd_record)

    summ = sub.add_parser("summary", help="print stability across recorded runs")
    summ.add_argument("--ledger", default=DEFAULT_LEDGER)
    summ.set_defaults(func=cmd_summary)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
