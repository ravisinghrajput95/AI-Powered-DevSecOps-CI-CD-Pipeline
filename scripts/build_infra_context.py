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

UPDATED 2026-06-23 (Checkov): Terraform/Checkov findings now flow through this SAME
builder rather than a separate build_terraform_context.py — Terraform-sec
folds into the existing infra-sec domain (both are "infrastructure
configuration," just two different layers: rendered K8s manifests vs.
cloud resource declarations) instead of being a wholly separate Option-A
domain. This is a deliberate correction from an earlier session attempt
that did split it out; that approach is retired. Everything kube-linter/
kubeconform-related below is UNCHANGED — Checkov findings are additive,
tagged with their own "component": "terraform" (vs. "infrastructure" for
kube-linter), so group_findings' (component, tool, rule_id, category) key
keeps them from ever cross-merging with kube-linter findings even when a
rule_id coincidentally matches.

UPDATED 2026-06-23 (Kyverno — REVERTED same day): Kyverno was briefly wired
in here as a third additive source, then moved back out — Kyverno (and
KubeArmor) are runtime/admission-time tools, grouped with DAST in a
separate runtime-security workflow instead, since everything in THIS
builder is static/build-time (kube-linter, kubeconform, checkov, terraform
validate all assess config/manifests without anything actually running).
If Kyverno findings need to land in a context object at all, that's a
decision for the runtime-security workflow's own builder, not this one.

KNOWN LIMITATIONS:
1. kubeconform is treated as a pass/fail validity GATE, not a source of
   findings — it answers "does this chart render to valid Kubernetes
   objects" as a fact, not a security judgment. Deliberately not mixed into
   the findings/severity model, per the design discussion that led here.
   `terraform validate` plays the identical role for Terraform — see
   terraform_validation below, kept as its own sibling field rather than
   merged into schema_validation, since they're factually answering
   different questions (K8s manifest schema validity vs. HCL/provider-
   schema validity) even though both are "is this config even valid".
2. infra-readiness.yml's --scan-status merge logic expects this combined
   shape (both "infrastructure" and "terraform" top-level keys) — see that
   workflow's updated artifact list.
3. Checkov's free/OSS checks have a confirmed real coverage gap: they flag
   literal "basic role" (Owner/Editor/Viewer) IAM grants but not other
   broad admin-level roles (e.g. roles/storage.admin, roles/container.admin
   granted to a default service account) — see normalize_checkov.py's
   CHECK_ID_MAPPING comment for CKV_GCP_117/49. A clean Checkov result does
   not mean "no overly-broad IAM grants exist".

Usage:
    build_infra_context.py --output infra_context.json \\
        --release-version <git-sha-or-tag> --repository <owner/repo> \\
        --kubelinter-findings normalized-kubelinter.json \\
        [--kubeconform-status kubeconform_status.json] \\
        [--checkov-findings normalized-checkov.json] \\
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
    parser.add_argument("--kubelinter-findings")
    parser.add_argument("--kubeconform-status")
    parser.add_argument("--checkov-findings")
    parser.add_argument("--terraform-validation")
    parser.add_argument("--scan-status")
    args = parser.parse_args()

    kubelinter_findings = load_json(args.kubelinter_findings, [])
    tagged = tag_findings(kubelinter_findings, "infrastructure")

    # Additive: Checkov findings tagged with their own component so they
    # group separately from kube-linter's, never cross-merging even on a
    # coincidentally-matching rule_id/category (see UPDATED note above).
    checkov_findings = load_json(args.checkov_findings, [])
    tagged += tag_findings(checkov_findings, "terraform")

    remediation_guide = {}
    grouped_findings = group_findings(tagged, remediation_guide)

    default_scan_status = {
        "infrastructure": {"kube-linter": "not_configured", "kubeconform": "not_configured"},
        "terraform": {"checkov": "not_configured", "terraform-validate": "not_configured"},
    }
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

    # terraform validate's equivalent gate — same default shape as
    # kubeconform's, kept as a separate sibling field (see KNOWN
    # LIMITATIONS #1 above for why it's not merged into schema_validation).
    default_terraform_validation = {"valid": "unknown", "error_count": None, "summary": None}
    terraform_validation = load_json(args.terraform_validation, default_terraform_validation)

    infra_context = {
        "release": {
            "version": args.release_version,
            "repository": args.repository,
            "components": ["infrastructure", "terraform"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "findings": grouped_findings,
        "remediation_guide": remediation_guide,
        "schema_validation": schema_validation,
        "terraform_validation": terraform_validation,
        "scan_status": scan_status,
        "release_statistics": compute_release_statistics(grouped_findings),
    }

    with open(args.output, "w") as f:
        json.dump(infra_context, f, indent=2)

    total_raw = len(kubelinter_findings) + len(checkov_findings)
    print(
        f"Built InfraContext: {len(kubelinter_findings)} kube-linter + {len(checkov_findings)} checkov "
        f"= {total_raw} raw findings -> {len(grouped_findings)} grouped entries -> {args.output}"
    )


if __name__ == "__main__":
    main()