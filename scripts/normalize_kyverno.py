#!/usr/bin/env python3
"""
Normalizes Kyverno CLI output (`kyverno apply <policies> --resource <dir>
--policy-report --output-format json`) into the shared schema:
{tool, severity, category, type, rule_id, message, file, line, confidence, recommendation}

** UNVERIFIED AGAINST REAL OUTPUT — read this before trusting it. **
Every other normalizer this session (kube-linter, checkov) was built
against a real, executed scan and iterated until zero unmatched-rule
warnings. Kyverno is the exception: the CLI binary's release downloads and
the GitHub API were both unreachable from the sandbox this was written in
(no live cluster, no `kyverno apply` execution possible), so this targets
the documented PolicyReport schema (the Kubernetes Policy Working Group's
open format, `wgpolicyk8s.io/v1alpha2`, confirmed consistent across
kyverno.io's docs/guides/reports/ and multiple released versions) rather
than a real captured example:
{
  "apiVersion": "wgpolicyk8s.io/v1alpha2",
  "kind": "PolicyReport",  // or ClusterPolicyReport, or a List of these
  "results": [
    {
      "policy": "disallow-privileged-containers",
      "rule": "privileged-containers",
      "resources": [{"apiVersion": "v1", "kind": "Pod", "name": "...", "namespace": "..."}],
      "result": "fail",  // pass | fail | warn | error | skip
      "message": "validation error: ... rule 'privileged-containers' failed at path /spec/..."
    }
  ],
  "summary": {"pass": 0, "fail": 1, "warn": 0, "error": 0, "skip": 0}
}
Treat the first real run's raw JSON as the actual source of truth, not this
docstring — if the shape differs, fix this file against that real output
the same way normalize_kubelinter.py/normalize_checkov.py were fixed
against theirs, and remove this warning once confirmed.

DEFENSIVE PARSING: handles a bare {results, summary} object, a `kind: List`
wrapper with multiple report objects in `items`, and a top-level JSON array
of report objects — without knowing which shape `kyverno apply` actually
emits for multiple resources, all three are at least attempted rather than
assuming one and silently producing zero findings on a real non-empty scan.

Only result == "fail" becomes a finding, mirroring checkov's failed_checks-
only and kube-linter's Reports-only approach. "warn" and "error" are NOT
silently dropped either — they're surfaced as findings too (with a note in
the message) since both indicate something a person should look at, even
though neither is the primary expected outcome for the policies used here
(none set `scored: false`, which is what produces "warn" instead of
"fail"). "pass" and "skip" are not findings.

CHECK_RULE_MAPPING is keyed on (policy, rule) since a single Kyverno
ClusterPolicy can define multiple independently-evaluated rules. Several
entries deliberately reuse categories ALREADY established by kube-linter/
checkov (e.g. "privileged-container", "run-as-root", "missing-resource-
limits") since Kyverno's Pod Security Standards checks assess the exact
same underlying concept — same reasoning as checkov's CKV_GCP_12 reusing
missing-pod-isolation. Severity per (policy, rule) is assigned directly by
this table rather than from Kyverno's own policies.kyverno.io/severity
annotation, which was confirmed uniformly "medium" across every policy
used here (not a usable per-finding signal) — see build_release_context.py
SEVERITY_NORMALIZATION's "kyverno" entry.

verify-image-cosign is a CUSTOM policy (not from the upstream kyverno/
policies library) written for this repo's actual keyless cosign signing
setup — see policies/kyverno/supply-chain/verify-image-cosign.yaml for why.

Usage:
    normalize_kyverno.py <output.json> <kyverno_report.json>
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from classify_finding import TYPE_BY_CATEGORY, DEFAULT_TYPE, classify_recommendation

# (severity, category) per (policy, rule). See docstring above for why
# severity is assigned here rather than read from Kyverno's own annotation.
CHECK_RULE_MAPPING = {
    # --- pod-security/baseline ---
    ("disallow-capabilities", "adding-capabilities"): ("medium", "excessive-capabilities"),
    ("disallow-host-namespaces", "host-namespaces"): ("critical", "host-namespace-sharing"),
    ("disallow-host-path", "host-path"): ("high", "host-path-mount"),
    ("disallow-host-ports", "host-ports-none"): ("medium", "excessive-exposure"),
    ("disallow-host-process", "host-process-containers"): ("medium", "host-process-container"),
    ("disallow-privileged-containers", "privileged-containers"): ("critical", "privileged-container"),
    ("disallow-proc-mount", "check-proc-mount"): ("high", "unmasked-proc-mount"),
    ("disallow-selinux", "selinux-type"): ("medium", "selinux-override"),
    ("disallow-selinux", "selinux-user-role"): ("medium", "selinux-override"),
    ("restrict-apparmor-profiles", "app-armor"): ("low", "unrestricted-apparmor-profile"),
    ("restrict-seccomp", "check-seccomp"): ("medium", "missing-seccomp-profile"),
    ("restrict-sysctls", "check-sysctls"): ("high", "excessive-capabilities"),

    # --- pod-security/restricted (additive on top of baseline) ---
    ("disallow-capabilities-strict", "require-drop-all"): ("high", "excessive-capabilities"),
    ("disallow-capabilities-strict", "adding-capabilities-strict"): ("high", "excessive-capabilities"),
    ("disallow-privilege-escalation", "privilege-escalation"): ("critical", "privilege-escalation"),
    ("require-run-as-non-root-user", "run-as-non-root-user"): ("high", "run-as-root"),
    ("require-run-as-nonroot", "run-as-non-root"): ("high", "run-as-root"),
    ("restrict-seccomp-strict", "check-seccomp-strict"): ("high", "missing-seccomp-profile"),
    ("restrict-volume-types", "restricted-volumes"): ("medium", "unrestricted-volume-types"),

    # --- best-practices ---
    ("require-requests-limits", "validate-resources"): ("medium", "missing-resource-limits"),

    # --- supply-chain (custom policy for this repo) ---
    ("verify-image-cosign", "verify-cosign-keyless-signature"): ("critical", "unsigned-container-image"),
}


def _result_to_finding(r):
    """Build one normalized finding from a single PolicyReport result entry,
    or return None if it's not finding-worthy (pass/skip)."""
    result = (r.get("result") or "").lower()
    if result not in ("fail", "warn", "error"):
        return None

    policy = r.get("policy", "unknown")
    rule = r.get("rule", "unknown")
    message = r.get("message", "")
    if result != "fail":
        message = f"[{result.upper()}] {message}"

    resources = r.get("resources") or []
    if resources:
        res = resources[0]
        kind = res.get("kind", "unknown")
        name = res.get("name", "unknown")
        namespace = res.get("namespace", "")
        file_field = f"{namespace}/{kind}/{name}" if namespace else f"{kind}/{name}"
    else:
        file_field = "unknown"

    key = (policy, rule)
    if key in CHECK_RULE_MAPPING:
        severity, category = CHECK_RULE_MAPPING[key]
    else:
        print(
            f"WARNING: unmatched kyverno (policy, rule) {key!r} (message: {message!r}) "
            f"— add it to CHECK_RULE_MAPPING in normalize_kyverno.py.",
            file=sys.stderr,
        )
        severity, category = "medium", "uncategorized"

    type_ = TYPE_BY_CATEGORY.get(category, DEFAULT_TYPE)
    recommendation = classify_recommendation(category)

    return {
        "tool": "kyverno",
        "severity": severity,
        "category": category,
        "type": type_,
        "rule_id": f"{policy}/{rule}",
        "message": message,
        "file": file_field,
        "line": None,  # rendered manifests, not literal source files with line numbers
        "confidence": "high",  # static policy evaluation against rendered manifests, not a heuristic guess
        "recommendation": recommendation,
    }


def _extract_results(report):
    """Defensively pull a flat list of result dicts out of whatever shape
    the real report turns out to be — see docstring's DEFENSIVE PARSING."""
    if isinstance(report, list):
        results = []
        for item in report:
            results.extend(_extract_results(item))
        return results

    if not isinstance(report, dict):
        return []

    if report.get("kind") == "List" and "items" in report:
        results = []
        for item in report["items"]:
            results.extend(_extract_results(item))
        return results

    return report.get("results", [])


def normalize_report(report):
    findings = []
    for r in _extract_results(report):
        finding = _result_to_finding(r)
        if finding is not None:
            findings.append(finding)
    return findings


def main():
    if len(sys.argv) != 3:
        print("Usage: normalize_kyverno.py <output.json> <kyverno_report.json>", file=sys.stderr)
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

    print(f"Normalized {len(findings)} kyverno findings -> {output_path}")


if __name__ == "__main__":
    main()