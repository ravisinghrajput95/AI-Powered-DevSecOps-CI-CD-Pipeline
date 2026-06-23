#!/usr/bin/env python3
"""
Assembles a TerraformContext object from Checkov findings for the same
Phase 2 AI analysis as ReleaseContext/InfraContext — kept as a SEPARATE
script rather than retrofitted into build_release_context.py or
build_infra_context.py.

This is the Option A decision applied a second time: terraform-sec is
purely additive. Nothing about the existing app-sec or infra-sec pipelines
changes as a result of this.

Reuses build_release_context.py's already-tool-agnostic functions
(tag_findings, group_findings, compute_release_statistics) directly via
import, same as build_infra_context.py does — the deterministic-
preprocessing rules apply identically regardless of domain.

KNOWN LIMITATIONS (mirrors build_infra_context.py's KNOWN LIMITATIONS
section):
1. terraform-security-scan.yaml now runs `terraform validate -json` as a
   companion validity gate (kubeconform's role for infra) and writes
   terraform_validation_status.json — pass it via --terraform-validation.
   Same separation as infra: validate answers "is this internally
   consistent HCL", not a security judgment, so it stays out of the
   findings/severity model entirely, same as kubeconform.
2. No --scan-status merge logic exists for a separate terraform-readiness
   orchestrator yet (unlike release-readiness.yml/infra-readiness.yml) —
   this script accepts already-prepared input files; an orchestrator
   workflow would be responsible for finding and downloading them.
3. Checkov's free/OSS checks have a confirmed real coverage gap: they flag
   literal "basic role" (Owner/Editor/Viewer) IAM grants but not other
   broad admin-level roles (e.g. roles/storage.admin, roles/container.admin
   granted to a default service account) — see normalize_checkov.py's
   CHECK_ID_MAPPING comment for CKV_GCP_117/49. A clean Checkov result does
   not mean "no overly-broad IAM grants exist".

Usage:
    build_terraform_context.py --output terraform_context.json \\
        --release-version <git-sha-or-tag> --repository <owner/repo> \\
        --checkov-findings normalized-checkov.json \\
        [--terraform-validation terraform_validation_status.json] \\
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
    parser.add_argument("--checkov-findings")
    parser.add_argument("--terraform-validation")
    parser.add_argument("--scan-status")
    args = parser.parse_args()

    findings = load_json(args.checkov_findings, [])
    tagged = tag_findings(findings, "terraform")

    remediation_guide = {}
    grouped_findings = group_findings(tagged, remediation_guide)

    default_scan_status = {"terraform": {"checkov": "not_configured", "terraform-validate": "not_configured"}}
    scan_status = load_json(args.scan_status, default_scan_status)
    if not args.scan_status:
        print(
            "NOTE: no --scan-status file provided. scan_status will be 'not_configured' "
            "rather than guessed.",
            file=sys.stderr,
        )

    # Factual pass/fail gate, not a finding — see KNOWN LIMITATIONS above.
    # Defaults to "unknown" only when --terraform-validation isn't passed
    # (e.g. running this script standalone outside the workflow); the
    # workflow itself always produces a real terraform_validation_status.json.
    default_validation = {"valid": "unknown", "error_count": None, "summary": None}
    terraform_validation = load_json(args.terraform_validation, default_validation)

    terraform_context = {
        "release": {
            "version": args.release_version,
            "repository": args.repository,
            "components": ["terraform"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "findings": grouped_findings,
        "remediation_guide": remediation_guide,
        "terraform_validation": terraform_validation,
        "scan_status": scan_status,
        "release_statistics": compute_release_statistics(grouped_findings),
    }

    with open(args.output, "w") as f:
        json.dump(terraform_context, f, indent=2)

    print(f"Built TerraformContext: {len(findings)} raw findings -> {len(grouped_findings)} grouped entries -> {args.output}")


if __name__ == "__main__":
    main()