#!/usr/bin/env python3
"""
Normalizes Checkov's JSON output (Terraform/GCP checks) into the shared
schema:
{tool, severity, category, type, rule_id, message, file, line, confidence, recommendation}

VERIFIED SCHEMA (confirmed via a real run against terraform/main.tf,
2026-06-23, checkov 3.3.1):
{
  "check_type": "terraform",
  "results": {
    "passed_checks": [...],
    "failed_checks": [
      {
        "check_id": "CKV_GCP_2",
        "check_name": "Ensure Google compute firewall ingress does not allow unrestricted ssh access",
        "resource": "google_compute_firewall.allow_all",
        "repo_file_path": "/terraform/main.tf",
        "file_line_range": [10, 29],
        "severity": null,
        "bc_check_id": null,
        "guideline": null
      }
    ],
    "skipped_checks": [...],
    "parsing_errors": []
  },
  "summary": {"passed": 30, "failed": 28, "skipped": 0, "parsing_errors": 0, ...}
}
Only failed_checks become findings — passed_checks are confirmations of
good config, not issues, same as kube-linter's "Reports" being the only
source of findings there.

IMPORTANT DEVIATION (same shape as kube-linter, confirmed independently
here): Checkov's OPEN-SOURCE output carries `severity: null` on every
check. `bc_check_id`/`bc_category`/`guideline` are null too — all four
require a live connection to the Bridgecrew/Prisma Cloud platform API,
which this pipeline doesn't have (confirmed: the run attempted and failed
to reach api0.prismacloud.io, and degraded gracefully rather than
crashing). So CHECK_ID_MAPPING below is a direct lookup keyed on Checkov's
own stable check_id (e.g. "CKV_GCP_2"), not a regex match against free
text — exactly the kube-linter precedent.

VALIDATED against this app's real terraform/ directory — every check_id
below was actually observed in a real scan (26 distinct IDs across 28
failed checks; two IDs — CKV_GCP_2 and CKV_GCP_69 — each fired on two
different resources). Any check_id NOT in this table falls through to the
loud "unmatched check" warning, same as every other tool's first pass.

`rule_id` is set to check_id (stable across Checkov versions, unlike
check_name which is free text Checkov could reword). `file` uses
repo_file_path (portable, not an absolute sandbox path). `line` is built
from file_line_range via the shared build_line_field helper.

Usage:
    normalize_checkov.py <output.json> <checkov_report.json>
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from classify_finding import TYPE_BY_CATEGORY, DEFAULT_TYPE, classify_recommendation, build_line_field

# (severity, category) per Checkov check_id. Severity uses this pipeline's
# already-normalized 5-tier scale directly (critical/high/medium/low/
# informational) — there's no native severity to preserve as
# original_severity for this tool, since Checkov's OSS build doesn't
# expose one (see docstring above).
CHECK_ID_MAPPING = {
    # Firewall rules with overly broad source_ranges/ports. Severity tiered
    # by what the exposed port/protocol actually grants: direct remote
    # shell/db access (ssh/rdp/mysql) is critical; ftp is high (cleartext
    # creds, less commonly needed); the unrestricted-port-80 check is
    # medium since this app is an intentionally public web app — the real
    # underlying problem is the single allow_all rule covering all 65535
    # ports, not port 80 specifically being reachable.
    "CKV_GCP_2": ("critical", "open-firewall-rule"),    # ssh unrestricted
    "CKV_GCP_3": ("critical", "open-firewall-rule"),    # rdp unrestricted
    "CKV_GCP_88": ("critical", "open-firewall-rule"),   # mysql unrestricted
    "CKV_GCP_75": ("high", "open-firewall-rule"),       # ftp unrestricted
    "CKV_GCP_77": ("high", "open-firewall-rule"),       # ftp port (separate check, same root cause)
    "CKV_GCP_106": ("medium", "open-firewall-rule"),    # http port 80 unrestricted

    # Confirmed (via reading Checkov's own check source, not just the
    # check_name string) to test node_config.workload_metadata_config.mode
    # == "GKE_METADATA". This app's node pool sets mode = "GCE_METADATA" —
    # the legacy mode that disables Workload Identity. This is the exact
    # Terraform-level root cause of the real production finding already
    # confirmed end-to-end in an earlier session (Workload Identity
    # disabled cluster-wide, both deployments under the bare default SA).
    "CKV_GCP_69": ("high", "workload-identity-disabled"),

    # Reuses the existing missing-pod-isolation category from kube-linter
    # — same underlying concept (lack of network segmentation), checked at
    # the cluster-enablement layer here instead of the per-pod layer.
    "CKV_GCP_12": ("medium", "missing-pod-isolation"),

    "CKV_GCP_13": ("high", "legacy-cluster-auth"),      # client cert auth enabled
    "CKV_GCP_7": ("high", "legacy-cluster-auth"),       # legacy ABAC enabled

    "CKV_GCP_1": ("high", "missing-cluster-logging-monitoring"),   # Stackdriver Logging
    "CKV_GCP_8": ("high", "missing-cluster-logging-monitoring"),   # Stackdriver Monitoring

    "CKV_GCP_20": ("medium", "missing-network-hardening"),  # master authorized networks
    "CKV_GCP_23": ("medium", "missing-network-hardening"),  # alias IP ranges
    "CKV_GCP_61": ("medium", "missing-network-hardening"),  # VPC flow logs / intranode visibility

    "CKV_GCP_65": ("low", "missing-rbac-hardening"),         # RBAC via Google Groups
    "CKV_GCP_66": ("medium", "missing-binary-authorization"),  # Binary Authorization

    # CKV_GCP_117/49 fired only on the literal roles/owner grant in the real
    # scan — NOT on the roles/storage.admin or roles/container.admin grants
    # also present in main.tf. Confirmed this is a real coverage gap, not a
    # normalizer bug: Checkov's free "basic roles" check specifically means
    # Owner/Editor/Viewer, and those two admin-level (but not "basic")
    # grants simply have no matching OSS check. Worth knowing this pipeline
    # will not flag every overly-broad IAM grant, only basic-role ones.
    "CKV_GCP_117": ("critical", "excessive-iam-privilege"),  # basic role (Owner) at project level
    "CKV_GCP_49": ("critical", "excessive-iam-privilege"),   # role can impersonate/manage SAs at project level

    "CKV_GCP_114": ("critical", "public-storage-bucket-risk"),  # public access prevention not enforced
    "CKV_GCP_29": ("high", "public-storage-bucket-risk"),       # uniform bucket-level access disabled
    "CKV_GCP_62": ("medium", "missing-storage-access-logging"),
    "CKV_GCP_78": ("low", "missing-bucket-versioning"),

    "CKV_GCP_68": ("medium", "node-hardening-gap"),     # Shielded VM Secure Boot
    "CKV_GCP_9": ("low", "node-pool-maintenance"),      # auto repair
    "CKV_GCP_10": ("low", "node-pool-maintenance"),     # auto upgrade
}


def normalize_report(report):
    findings = []

    failed = report.get("results", {}).get("failed_checks", [])
    # results.failed_checks can also be a bare list at the top level if a
    # single-check-type run is summarized differently in some Checkov
    # versions — fall back defensively rather than assuming the nested
    # shape always holds.
    if not failed and isinstance(report.get("results"), list):
        failed = report["results"]

    for c in failed:
        check_id = c.get("check_id", "unknown")
        message = c.get("check_name", "")
        resource = c.get("resource", "unknown")
        file_path = c.get("repo_file_path") or c.get("file_path") or "unknown"
        line_range = c.get("file_line_range") or [None, None]

        if check_id in CHECK_ID_MAPPING:
            severity, category = CHECK_ID_MAPPING[check_id]
        else:
            print(
                f"WARNING: unmatched checkov check_id {check_id!r} (check_name: {message!r}, "
                f"resource: {resource!r}) — add it to CHECK_ID_MAPPING in normalize_checkov.py.",
                file=sys.stderr,
            )
            severity, category = "medium", "uncategorized"

        type_ = TYPE_BY_CATEGORY.get(category, DEFAULT_TYPE)
        recommendation = classify_recommendation(category)

        findings.append({
            "tool": "checkov",
            "severity": severity,
            "category": category,
            "type": type_,
            "rule_id": check_id,
            "message": f"{message} ({resource})",
            "file": file_path,
            "line": build_line_field(line_range[0], line_range[1]),
            "confidence": "high",  # static analysis of declared resource config, not a heuristic guess
            "recommendation": recommendation,
        })

    return findings


def main():
    if len(sys.argv) != 3:
        print("Usage: normalize_checkov.py <output.json> <checkov_report.json>", file=sys.stderr)
        sys.exit(1)

    output_path = sys.argv[1]
    report_path = sys.argv[2]

    try:
        with open(report_path) as f:
            report = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"WARNING: could not read {report_path}: {e}", file=sys.stderr)
        report = {}

    findings = normalize_report(report)

    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"Normalized {len(findings)} checkov findings -> {output_path}")


if __name__ == "__main__":
    main()