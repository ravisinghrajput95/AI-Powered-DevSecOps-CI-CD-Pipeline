#!/usr/bin/env python3
"""
Normalizes kube-linter's JSON output into the shared schema:
{tool, severity, category, type, rule_id, message, file, line, confidence, recommendation}

VERIFIED SCHEMA (confirmed via a real working example, 2026-06-22):
{
  "Reports": [
    {
      "Check": "env-var-secret",
      "Remediation": "Do not use raw secrets in environment variables...",
      "Diagnostic": {"Message": "environment variable DB_PASSWORD_SECRET in container \"x\" found"},
      "Object": {
        "K8sObject": {
          "GroupVersionKind": {"Kind": "Deployment"},
          "Name": "insecure-app",
          "Namespace": "frontend"
        },
        "Metadata": {"FilePath": "..."}
      }
    }
  ]
}
A scan with zero findings still produces this structure with an empty
"Reports" list — that is a normal clean result, not a parsing failure.

IMPORTANT DEVIATION FROM EVERY OTHER NORMALIZER IN THIS PIPELINE: kube-linter's
JSON carries NO per-finding severity field at all. Severity here is an
inherent property of the CHECK ITSELF (e.g. "privileged-container" is just
always serious), not something attached to each report instance the way
Snyk/SonarCloud/ZAP all had. CHECK_NAME_MAPPING below is therefore a direct
lookup keyed on the stable check name (rule_id), not a regex match against
free text — check names are kube-linter's own stable identifiers, so this
is more reliable than text pattern matching, not less.

UNVALIDATED against this app's real Helm charts — this mapping covers
kube-linter's well-known default checks based on documentation, but the
first real scan is what actually confirms it. Any check not in the table
falls through to the loud "unmatched check" warning below, same pattern as
every other tool's first pass this session.

`rule_id` is set to the check name (e.g. "privileged-container"), and
`file` is built from the K8s object's Namespace/Kind/Name, since these are
rendered manifests, not literal source files with line numbers — `line` is
always None here.

Usage:
    normalize_kubelinter.py <output.json> <kubelinter_report.json>
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from classify_finding import TYPE_BY_CATEGORY, DEFAULT_TYPE, classify_recommendation

# (severity, category) per check name. Severity here uses this pipeline's
# already-normalized 5-tier scale directly (critical/high/medium/low/
# informational) rather than a tool-native string that needs translating —
# there's no native severity to preserve as original_severity for this tool,
# since kube-linter doesn't have one.
CHECK_NAME_MAPPING = {
    "privileged-container": ("critical", "privileged-container"),
    "privilege-escalation-container": ("critical", "privilege-escalation"),
    "host-network": ("critical", "host-namespace-sharing"),
    "host-ipc": ("critical", "host-namespace-sharing"),
    "host-pid": ("critical", "host-namespace-sharing"),
    "run-as-non-root": ("high", "run-as-root"),
    "env-var-secret": ("high", "secret-in-env-var"),
    "unsafe-sysctls": ("high", "excessive-capabilities"),
    "drop-net-raw-capability": ("medium", "excessive-capabilities"),
    "unset-cpu-requirements": ("medium", "missing-resource-limits"),
    "unset-memory-requirements": ("medium", "missing-resource-limits"),
    "no-read-only-root-fs": ("medium", "writable-root-filesystem"),
    "default-service-account": ("medium", "default-service-account-usage"),
    "non-existent-service-account": ("medium", "default-service-account-usage"),
    "latest-tag": ("medium", "mutable-image-tag"),
    "exposed-services": ("medium", "excessive-exposure"),
    "ssh-port": ("medium", "excessive-exposure"),
    "non-isolated-pod": ("medium", "missing-pod-isolation"),
    "no-liveness-probe": ("low", "missing-health-probe"),
    "no-readiness-probe": ("low", "missing-health-probe"),
    "dangling-service": ("low", "missing-pod-isolation"),
    "required-annotation-email": ("low", "informational-finding"),
    "mismatching-selector": ("low", "informational-finding"),
}


def normalize_report(report):
    findings = []

    for r in report.get("Reports", []):
        check = r.get("Check", "unknown")
        message = r.get("Diagnostic", {}).get("Message", "")
        tool_remediation = r.get("Remediation", "")

        k8s_obj = r.get("Object", {}).get("K8sObject", {})
        kind = k8s_obj.get("GroupVersionKind", {}).get("Kind", "unknown")
        name = k8s_obj.get("Name", "unknown")
        namespace = k8s_obj.get("Namespace", "")
        file_field = f"{namespace}/{kind}/{name}" if namespace else f"{kind}/{name}"

        if check in CHECK_NAME_MAPPING:
            severity, category = CHECK_NAME_MAPPING[check]
        else:
            print(
                f"WARNING: unmatched kube-linter check {check!r} (message: {message!r}) "
                f"— add it to CHECK_NAME_MAPPING in normalize_kubelinter.py.",
                file=sys.stderr,
            )
            severity, category = "medium", "uncategorized"

        type_ = TYPE_BY_CATEGORY.get(category, DEFAULT_TYPE)
        # kube-linter's own remediation text is generally good and specific
        # (it's written per-check by the tool authors) — prefer it over the
        # category-level generic guidance where available.
        recommendation = tool_remediation or classify_recommendation(category)

        findings.append({
            "tool": "kube-linter",
            "severity": severity,
            "category": category,
            "type": type_,
            "rule_id": check,
            "message": message,
            "file": file_field,
            "line": None,
            "confidence": "high",  # static analysis of rendered manifests, not a heuristic guess
            "recommendation": recommendation,
        })

    return findings


def main():
    if len(sys.argv) != 3:
        print("Usage: normalize_kubelinter.py <output.json> <kubelinter_report.json>", file=sys.stderr)
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

    print(f"Normalized {len(findings)} kube-linter findings -> {output_path}")


if __name__ == "__main__":
    main()