#!/usr/bin/env python3
"""
Normalizes Kyverno's live `PolicyReport`/`ClusterPolicyReport` CRD data
(`kubectl get policyreport -A -o json` + `kubectl get clusterpolicyreport
-o json`, merged into one `kind: List` object by runtime-security-scan.yaml)
into the shared schema:
{tool, severity, category, type, rule_id, message, file, line, confidence, recommendation}

VERIFIED AGAINST REAL OUTPUT (2026-06-23) — this has now actually run
against the live cloudcart-dev cluster, not just the documented schema.
Two real bugs surfaced and were fixed here as a direct result (both are
the kind of thing only real data catches, same pattern as every other
normalizer this session):

1. Kyverno auto-generates an "autogen-<rule>" sibling for every rule that
   targets kinds: [Pod] (so the same check also applies to Deployment/
   StatefulSet/DaemonSet/Job/CronJob pod templates, not just bare Pods).
   A real capture showed e.g. "autogen-require-drop-all" right alongside
   "require-drop-all" — CHECK_RULE_MAPPING only had the bare names, so
   every autogen- variant fell through to "uncategorized". Fixed by
   stripping the "autogen-" prefix before the lookup (see
   _result_to_finding) rather than doubling every table entry.
2. A resource-scoped PolicyReport (one report per resource — the common
   case for policies matching kinds: [Pod]) puts resource identity in a
   top-level `scope` field (apiVersion/kind/name/namespace/uid), NOT in
   each result's `resources[]` array the way the original (pre-real-data)
   version of this file assumed from the documented examples. Real
   results only carry {category, message, policy, properties, result,
   rule, scored, severity, source, timestamp} — no `resources` key at
   all. Fixed by threading the parent report's `scope` through
   _extract_results as a fallback.

Real schema, confirmed:
{
  "apiVersion": "wgpolicyk8s.io/v1alpha2",
  "kind": "PolicyReport",
  "metadata": {"namespace": "cloudcart", "name": "<uuid>"},
  "scope": {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "cloudcart-backend-...", "namespace": "cloudcart", "uid": "..."},
  "results": [
    {"policy": "disallow-capabilities-strict", "rule": "autogen-require-drop-all",
     "result": "fail", "message": "validation failure: Containers must drop `ALL` capabilities.",
     "category": "Pod Security Standards (Restricted)", "severity": "medium",
     "source": "kyverno", "scored": true, "properties": {"process": "background scan"}}
  ],
  "summary": {"error": 0, "fail": 5, "pass": 15, "skip": 0, "warn": 0}
}

ALSO CONFIRMED FROM THE SAME REAL RUN: none of the 19 ClusterPolicy files
originally had namespace scoping in their `match` block, so Kyverno's
background scanner evaluated the ENTIRE cluster, not just cloudcart —
155 PolicyReports came back, only 34 of them actually about cloudcart
(the rest: kube-system, GKE-managed components, kyverno/kubearmor's own
pods, the monitoring stack). Fixed at the SOURCE, not here — every policy
under policies/kyverno/ now has `namespaces: ["cloudcart"]` added to its
match.any[].resources block, so this normalizer should only ever see
cloudcart-scoped reports going forward. Not enforced defensively in this
file itself — if a future policy gets added without that scoping, the
fix is in the policy YAML, not a filter bolted on here.

DEFENSIVE PARSING: handles a bare {results, summary} object, a `kind: List`
wrapper with multiple report objects in `items` (the real shape produced
by the workflow's jq merge step), and a top-level JSON array of report
objects.

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

# This app's namespace — see the defensive filter in _result_to_finding.
EXPECTED_NAMESPACE = "cloudcart"

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


def _result_to_finding(r, scope=None):
    """Build one normalized finding from a single PolicyReport result entry,
    or return None if it's not finding-worthy (pass/skip).

    `scope` is the parent report's top-level scope object (apiVersion/kind/
    name/namespace/uid) — see docstring's "FIXED 2026-06-23 (scope)" note.
    """
    result = (r.get("result") or "").lower()
    if result not in ("fail", "warn", "error"):
        return None

    policy = r.get("policy", "unknown")
    rule = r.get("rule", "unknown")
    message = r.get("message", "")
    if result != "fail":
        message = f"[{result.upper()}] {message}"

    # Real captured reports carry per-result resources[] sometimes, but for
    # reports scoped to exactly one resource (the common case for our
    # ClusterPolicies, which all match kinds: [Pod]), resource identity
    # lives in the report-level `scope` field instead — confirmed via a
    # real capture, not the original docs examples this was first built
    # against (see docstring). Try resources[] first, fall back to scope.
    resources = r.get("resources") or []
    if resources:
        res = resources[0]
        kind = res.get("kind", "unknown")
        name = res.get("name", "unknown")
        namespace = res.get("namespace", "")
    elif scope:
        kind = scope.get("kind", "unknown")
        name = scope.get("name", "unknown")
        namespace = scope.get("namespace", "")
    else:
        kind = name = namespace = None

    if kind and name:
        file_field = f"{namespace}/{kind}/{name}" if namespace else f"{kind}/{name}"
    else:
        file_field = "unknown"

    # Defensive second layer, not the primary fix: runtime-security-scan.yaml
    # now queries `kubectl get policyreport -n cloudcart` (not -A), which is
    # the actual fix for the cluster-wide-noise bug confirmed via a real
    # run (kube-system/monitoring/etc. reports were silently merged into
    # the SAME grouped finding as genuine cloudcart violations, since
    # group_findings' key doesn't include namespace — a rule showing "77
    # occurrences" was actually 28 real + 49 unrelated cluster noise).
    # This check doesn't replace that fix; it's a loud backstop in case a
    # future workflow edit reverts to -A or ClusterPolicyReport ever
    # carries an unexpected namespace — silently passing through
    # unrelated-namespace data here would reintroduce the exact same bug
    # with no signal that it happened.
    if namespace and namespace != EXPECTED_NAMESPACE:
        print(
            f"WARNING: dropping kyverno result for namespace {namespace!r} (expected "
            f"only {EXPECTED_NAMESPACE!r}) — policy={policy!r} rule={rule!r}. If this "
            f"fires often, check whether runtime-security-scan.yaml's PolicyReport query "
            f"is still scoped to -n {EXPECTED_NAMESPACE}.",
            file=sys.stderr,
        )
        return None

    # Kyverno auto-generates an "autogen-<rule>" sibling for every rule
    # that targets kinds: [Pod], applying the same check to Deployment/
    # StatefulSet/DaemonSet/Job/CronJob pod templates too — confirmed via
    # real findings (e.g. "autogen-require-drop-all" alongside "require-
    # drop-all"). Same underlying check either way, so strip the prefix
    # before the lookup rather than doubling every CHECK_RULE_MAPPING
    # entry. rule_id keeps the real (possibly autogen-) name for
    # traceability — only the lookup key is normalized.
    lookup_rule = rule[len("autogen-"):] if rule.startswith("autogen-") else rule
    key = (policy, lookup_rule)
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
    """Defensively pull a flat list of (result, scope) tuples out of
    whatever shape the real report turns out to be — see docstring's
    DEFENSIVE PARSING. `scope` is threaded through so _result_to_finding
    can fall back to it for resource identity when results[].resources is
    absent (the common real case — see docstring's FIXED note)."""
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

    scope = report.get("scope")
    return [(r, scope) for r in report.get("results", [])]


def normalize_report(report):
    findings = []
    for r, scope in _extract_results(report):
        finding = _result_to_finding(r, scope)
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