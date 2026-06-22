#!/usr/bin/env python3
"""
Assembles an InfraContext object from kube-linter (and kubeconform's
pass/fail gate) for the same Phase 2 AI analysis as ReleaseContext — kept
as a SEPARATE script rather than retrofitted into build_release_context.py.

This is the Option A decision: infra is purely additive. Nothing about the
existing app-sec/runtime ReleaseContext pipeline (release-readiness.yml,
build_release_context.py's own CLI/output) changes as a result of this.

Reuses build_release_context.py's already-tool-agnostic functions
(tag_findings, group_findings, compute_release_statistics) directly via
import rather than duplicating this logic — the deterministic-preprocessing
rules (the 3-question test: deterministic? Python better? materially
improves reasoning?) apply identically regardless of domain, so there's no
reason for infra to reinvent grouping/severity-normalization/statistics.

KNOWN LIMITATIONS:
1. kubeconform is treated as a pass/fail validity GATE, not a source of
   findings — it answers "does this chart render to valid Kubernetes
   objects" as a fact, not a security judgment. Deliberately not mixed into
   the findings/severity model, per the design discussion that led here.
2. No --scan-status merge logic exists yet for a separate infra-readiness.yml
   orchestrator (unlike release-readiness.yml's SHA-matching download logic)
   — this script accepts already-prepared input files; the orchestrator
   workflow is what's responsible for finding and downloading them.

Usage:
    build_infra_context.py --output infra_context.json \\
        --release-version <git-sha-or-tag> --repository <owner/repo> \\
        --kubelinter-findings normalized-kubelinter.json \\
        [--kubeconform-status kubeconform_status.json] \\
        [--scan-status scan_status.json]
"""
import argparse
import json
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_release_context import tag_findings, group_findings, compute_release_statistics, load_json


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--kubelinter-findings")
    parser.add_argument("--kubeconform-status")
    parser.add_argument("--scan-status")
    args = parser.parse_args()

    findings = load_json(args.kubelinter_findings, [])
    tagged = tag_findings(findings, "infrastructure")

    remediation_guide = {}
    grouped_findings = group_findings(tagged, remediation_guide)

    default_scan_status = {"infrastructure": {"kube-linter": "not_configured", "kubeconform": "not_configured"}}
    scan_status = load_json(args.scan_status, default_scan_status)
    if not args.scan_status:
        print(
            "NOTE: no --scan-status file provided. scan_status will be 'not_configured' "
            "rather than guessed.",
            file=sys.stderr,
        )

    # Factual pass/fail gate, not a finding — see KNOWN LIMITATIONS above.
    default_kubeconform = {"valid": "unknown", "error_count": None, "summary": None}
    schema_validation = load_json(args.kubeconform_status, default_kubeconform)

    infra_context = {
        "release": {
            "version": args.release_version,
            "repository": args.repository,
            "components": ["infrastructure"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "findings": grouped_findings,
        "remediation_guide": remediation_guide,
        "schema_validation": schema_validation,
        "scan_status": scan_status,
        "release_statistics": compute_release_statistics(grouped_findings),
    }

    with open(args.output, "w") as f:
        json.dump(infra_context, f, indent=2)

    print(f"Built InfraContext: {len(findings)} raw findings -> {len(grouped_findings)} grouped entries -> {args.output}")


if __name__ == "__main__":
    main()