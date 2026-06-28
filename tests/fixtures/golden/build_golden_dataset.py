#!/usr/bin/env python3
"""
Generates the permanent golden ReleaseContext fixtures used by the test
suite. Run once, by hand, whenever a scenario needs to change — NOT run
automatically by the test suite itself. The fixtures it produces are
checked into git as static files; tests load and assert against those
static files, not against a live regeneration.

Why generate-once-and-commit rather than regenerate at test time: these
are regression fixtures. If they were regenerated dynamically using the
same pipeline functions the tests are trying to guard, a bug introduced
into those functions would silently "fix" the fixture instead of being
caught by it — the one thing a regression fixture exists to prevent.

Why THROUGH the real pipeline functions at all, rather than hand-typed
JSON: hand-typing risks exactly the kind of drift this whole platform has
spent this session eliminating — a fixture's finding_id, domain, or
severity could quietly stop matching what the real pipeline would
actually produce for the same input, and nothing would catch it. Building
raw (pre-grouping) findings and running them through tag_findings ->
assign_domain -> group_findings -> compute_release_statistics ->
normalize_scan_status -> derive_verification_status — the exact same
functions compose_release_context.py calls in production — means a
fixture is only ever wrong in the same way production would be wrong, in
which case the fixture and a real regression go hand in hand.

Severity values below use each tool's REAL native vocabulary (confirmed
against SEVERITY_NORMALIZATION in build_release_context.py), not generic
high/critical strings — tag_findings() calls normalize_severity()
internally, so a generic string here would silently default to "medium"
with a logged warning, exactly the mistake this project already made once
this session with synthetic CodeQL/GitGuardian data.
"""
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/../../../scripts")
from build_release_context import tag_findings, assign_domain, group_findings, compute_release_statistics
from compose_release_context import normalize_scan_status, derive_verification_status

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = "example-org/example-service"


def build_release_context(scenario_name, version, raw_findings_by_component, scan_status_raw, supply_chain_raw=None, components=None):
    """raw_findings_by_component: {component: [raw_finding_dict, ...]}.
    Each raw finding needs tool/severity(native)/category/type/confidence/
    rule_id/message, exactly what a normalizer would produce — this
    function does the SAME tagging+grouping production does, nothing
    extra."""
    all_tagged = []
    for component, raw_findings in raw_findings_by_component.items():
        all_tagged.extend(tag_findings(raw_findings, component))

    remediation_guide = {}
    grouped = group_findings(all_tagged, remediation_guide)
    for f in grouped:
        f["domain"] = assign_domain(f)

    grouped.sort(key=lambda f: (f["domain"], f["severity"], f["category"], f["tool"]))

    stats = compute_release_statistics(grouped)
    scan_status = normalize_scan_status(scan_status_raw)

    supply_chain = supply_chain_raw or {}
    for entry in supply_chain.values():
        entry["verification_status"] = derive_verification_status(entry)

    # Fixed, not datetime.now() — these are regression fixtures, not real
    # events. A real "when was this generated" timestamp would make every
    # regeneration produce a different file even with zero code changes,
    # which would make CI's drift-check (regenerate fresh, diff against
    # committed) always report a false regression. Caught this before it
    # ever ran in CI, not after.
    generated_at = "2026-01-01T00:00:00+00:00"
    context = {
        "schema_version": "1.0.0",
        "release": {
            "version": version,
            "repository": REPO,
            "components": components or sorted(raw_findings_by_component.keys()),
            "generated_at": generated_at,
        },
        "provenance": {
            "application_security": {"source_version": version, "source_generated_at": generated_at, "note": "golden fixture — synthetic provenance"},
            "infrastructure_security": {"source_version": version, "source_generated_at": generated_at, "version_matches_application_security": True, "commits_behind": 0, "commits_behind_note": "golden fixture"},
            "runtime_security": {"zap": {"run_id": "golden", "scanned_at": generated_at, "days_stale": 0}, "kyverno": {"run_id": "golden", "scanned_at": generated_at, "days_stale": 0}, "kubearmor": {"run_id": "golden", "scanned_at": generated_at, "days_stale": 0}},
        },
        "findings": grouped,
        "remediation_guide": remediation_guide,
        "scan_status": scan_status,
        "release_statistics": stats,
        "signal_availability": {
            "severity": "available_per_finding", "confidence": "available_per_finding",
            "fix_availability": "available_per_finding_where_applicable", "delta_status": "not_collected",
            "reachability": "not_collected", "exploitability": "not_collected",
            "business_impact": "not_collected", "internet_exposure": "not_collected",
        },
        "sbom_summary": {"backend": {"total_packages": 0}, "frontend": {"total_packages": 0}},
        "dependency_summary": {},
        "supply_chain": supply_chain,
        "schema_validation": {"valid": True, "summary": {"resources": [], "summary": {"valid": 1, "invalid": 0, "errors": 0, "skipped": 0}}},
        "terraform_validation": {"valid": True, "error_count": 0, "summary": {"format_version": "1.0", "valid": True, "error_count": 0, "warning_count": 0, "diagnostics": []}},
    }
    with open(f"{OUTPUT_DIR}/{scenario_name}.json", "w") as f:
        json.dump(context, f, indent=2)
    print(f"{scenario_name}: {len(grouped)} findings, by_domain={stats['by_domain']}, by_severity={stats['by_severity']}")
    return context


def rule(tool, severity, category, ftype, confidence, rule_id, message, **extra):
    d = {"tool": tool, "severity": severity, "category": category, "type": ftype, "confidence": confidence, "rule_id": rule_id, "message": message, "recommendation": f"Fix: {message}"}
    d.update(extra)
    return d


def main():
    # ── 1. Clean release ──────────────────────────────────────────────
    build_release_context(
        "clean_release", "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
        {
            "infrastructure": [rule("kube-linter", "informational", "code-quality", "quality", "high", "missing-annotation", "Deployment missing a recommended annotation")],
            "deployed-app": [],
        },
        {"backend": {"codeql": "success", "sonarcloud": "success", "gitguardian": "success", "snyk_sca": "success"},
         "frontend": {"codeql": "success", "sonarcloud": "success", "gitguardian": "success", "snyk_sca": "success"},
         "deployed-app": {"zap": "success", "kyverno": "success", "kubearmor": "success"},
         "infrastructure": {"kube-linter": "success", "kubeconform": "success"},
         "terraform": {"checkov": "success", "terraform-validate": "success"}},
        {"backend": {"image_signed": True, "signature_verified": True, "verification_notes": "verified"},
         "frontend": {"image_signed": True, "signature_verified": True, "verification_notes": "verified"}},
    )

    # ── 2. Moderate-risk release ──────────────────────────────────────
    build_release_context(
        "moderate_risk_release", "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222",
        {
            "infrastructure": [rule("kube-linter", "medium", "missing-resource-limits", "security", "high", "no-resource-limits", "Container has no CPU/memory limits set")],
            "terraform": [rule("checkov", "low", "missing-storage-access-logging", "security", "high", "CKV_GCP_62", "Storage bucket has access logging disabled")],
            "deployed-app": [rule("zap", "medium", "missing-security-headers", "security", "medium", "10038", "Content Security Policy header not set"),
                              rule("zap", "low", "insecure-caching", "security", "medium", "10015", "Cache-control header not set on a response with sensitive content")],
            "backend": [rule("snyk", "medium", "vulnerable-dependency", "security", "high", "SNYK-PYTHON-REQUESTS-1234", "requests has a known moderate-severity CVE", package_name="requests", package_version="2.28.0", package_manager="pip")],
        },
        {"backend": {"codeql": "success", "sonarcloud": "success", "gitguardian": "success", "snyk_sca": "success"},
         "frontend": {"codeql": "success", "sonarcloud": "success", "gitguardian": "success", "snyk_sca": "success"},
         "deployed-app": {"zap": "success", "kyverno": "success", "kubearmor": "success"},
         "infrastructure": {"kube-linter": "success", "kubeconform": "success"},
         "terraform": {"checkov": "success", "terraform-validate": "success"}},
        {"backend": {"image_signed": True, "signature_verified": True, "verification_notes": "verified"},
         "frontend": {"image_signed": True, "signature_verified": True, "verification_notes": "verified"}},
    )

    # ── 3. Critical release ───────────────────────────────────────────
    build_release_context(
        "critical_release", "cccc3333cccc3333cccc3333cccc3333cccc3333",
        {
            "terraform": [rule("checkov", "critical", "excessive-iam-privilege", "security", "high", "CKV_GCP_117", "Project-level Owner role granted to a service account"),
                           rule("checkov", "critical", "open-firewall-rule", "security", "high", "CKV_GCP_3", "Firewall rule allows unrestricted SSH from 0.0.0.0/0")],
            "deployed-app": [rule("kyverno", "critical", "privilege-escalation", "security", "high", "disallow-privilege-escalation", "Privilege escalation is enabled on 12 running pods"),
                              rule("kyverno", "critical", "run-as-root", "security", "high", "require-run-as-nonroot", "Containers running as root on 12 pods"),
                              rule("kubearmor", "high", "unauthorized-file-access", "security", "high", "ksp-audit-sensitive-files", "Process accessed /etc/shadow")],
        },
        {"backend": {"codeql": "skipped", "sonarcloud": "skipped", "gitguardian": "skipped", "snyk_sca": "skipped"},
         "frontend": {"codeql": "skipped", "sonarcloud": "skipped", "gitguardian": "skipped", "snyk_sca": "skipped"},
         "deployed-app": {"zap": "success", "kyverno": "success", "kubearmor": "success"},
         "infrastructure": {"kube-linter": "success", "kubeconform": "success"},
         "terraform": {"checkov": "success", "terraform-validate": "success"}},
        {"backend": {"image_signed": "unknown", "signature_verified": False, "verification_notes": "MANIFEST_UNKNOWN"},
         "frontend": {"image_signed": "unknown", "signature_verified": False, "verification_notes": "MANIFEST_UNKNOWN"}},
    )

    # ── 4. Infrastructure-heavy ───────────────────────────────────────
    build_release_context(
        "infrastructure_heavy", "dddd4444dddd4444dddd4444dddd4444dddd4444",
        {
            "terraform": [
                rule("checkov", "critical", "excessive-iam-privilege", "security", "high", "CKV_GCP_117", "Project Owner role granted"),
                rule("checkov", "high", "workload-identity-disabled", "security", "high", "CKV_GCP_69", "Workload Identity disabled on GKE cluster"),
                rule("checkov", "high", "open-firewall-rule", "security", "high", "CKV_GCP_3", "Firewall allows unrestricted SSH"),
                rule("checkov", "medium", "missing-bucket-versioning", "security", "high", "CKV_GCP_78", "Storage bucket versioning disabled"),
                rule("checkov", "medium", "missing-binary-authorization", "security", "high", "CKV_GCP_66", "Binary Authorization not enabled"),
                rule("checkov", "low", "node-pool-maintenance", "security", "medium", "CKV_GCP_24", "Node pool auto-upgrade disabled"),
            ],
            "infrastructure": [
                rule("kube-linter", "medium", "missing-resource-limits", "security", "high", "no-resource-limits", "Deployment has no resource limits"),
                rule("kube-linter", "low", "missing-readiness-probe", "quality", "high", "no-readiness-probe", "Container has no readiness probe"),
            ],
        },
        {"backend": {"codeql": "success", "sonarcloud": "success", "gitguardian": "success", "snyk_sca": "success"},
         "frontend": {"codeql": "success", "sonarcloud": "success", "gitguardian": "success", "snyk_sca": "success"},
         "deployed-app": {"zap": "success", "kyverno": "success", "kubearmor": "success"},
         "infrastructure": {"kube-linter": "success", "kubeconform": "success"},
         "terraform": {"checkov": "success", "terraform-validate": "success"}},
        {"backend": {"image_signed": True, "signature_verified": True, "verification_notes": "verified"},
         "frontend": {"image_signed": True, "signature_verified": True, "verification_notes": "verified"}},
    )

    # ── 5. Runtime-heavy ──────────────────────────────────────────────
    build_release_context(
        "runtime_heavy", "eeee5555eeee5555eeee5555eeee5555eeee5555",
        {
            "deployed-app": [
                rule("kyverno", "critical", "privilege-escalation", "security", "high", "disallow-privilege-escalation", "Privilege escalation enabled across 18 pods"),
                rule("kyverno", "critical", "run-as-root", "security", "high", "require-run-as-nonroot", "Containers running as root across 18 pods"),
                rule("kyverno", "high", "missing-seccomp-profile", "security", "high", "restrict-seccomp-strict", "No seccomp profile set"),
                rule("kyverno", "high", "excessive-capabilities", "security", "high", "disallow-capabilities-strict", "Linux capabilities not dropped"),
                rule("kyverno", "medium", "unsigned-container-image", "security", "high", "verify-image-cosign", "Image signature could not be verified"),
                rule("kubearmor", "high", "unauthorized-process-execution", "security", "high", "ksp-block-shell-exec", "Shell execution detected in backend container"),
                rule("kubearmor", "medium", "unauthorized-network-activity", "security", "medium", "ksp-audit-icmp", "Unexpected ICMP traffic from pod"),
                rule("zap", "medium", "missing-security-headers", "security", "medium", "10038", "CSP header missing"),
                rule("zap", "low", "info-disclosure", "security", "medium", "10037", "Server version header disclosed"),
            ],
        },
        {"backend": {"codeql": "success", "sonarcloud": "success", "gitguardian": "success", "snyk_sca": "success"},
         "frontend": {"codeql": "success", "sonarcloud": "success", "gitguardian": "success", "snyk_sca": "success"},
         "deployed-app": {"zap": "success", "kyverno": "success", "kubearmor": "success"},
         "infrastructure": {"kube-linter": "success", "kubeconform": "success"},
         "terraform": {"checkov": "success", "terraform-validate": "success"}},
        {"backend": {"image_signed": True, "signature_verified": True, "verification_notes": "verified"},
         "frontend": {"image_signed": True, "signature_verified": True, "verification_notes": "verified"}},
    )

    # ── 6. Application-heavy — the never-tested-with-real-data domain ──
    build_release_context(
        "application_heavy", "ffff6666ffff6666ffff6666ffff6666ffff6666",
        {
            "backend": [
                rule("codeql", "error", "sql-injection", "security", "high", "py/sql-injection", "User input flows into a SQL query without sanitization", file="backend/routes/orders.py"),
                rule("codeql", "warning", "code-quality", "quality", "medium", "py/unused-import", "Unused import detected"),
                rule("sonarcloud", "blocker", "secret-exposure", "security", "high", "python:S6418", "Hardcoded credential detected in source"),
                rule("sonarcloud", "medium", "code-quality", "quality", "high", "python:S1192", "String literal duplicated 5 times"),
                rule("gitguardian", "valid", "secret-exposure", "security", "high", "generic_high_entropy_secret", "Confirmed live API key found in commit history"),
                rule("snyk", "critical", "vulnerable-dependency", "security", "high", "SNYK-PYTHON-FLASK-9999", "Flask has a known critical CVE", package_name="flask", package_version="2.0.1", package_manager="pip"),
                rule("snyk", "high", "vulnerable-dependency", "security", "high", "SNYK-PYTHON-FLASK-8888", "Flask has a second, separate known CVE at the same version", package_name="flask", package_version="2.0.1", package_manager="pip"),
            ],
            "frontend": [
                rule("codeql", "warning", "xss", "security", "medium", "js/xss-through-dom", "Potential DOM-based XSS via innerHTML"),
                rule("sonarcloud", "high", "code-quality", "quality", "high", "javascript:S3776", "Function has excessive cognitive complexity"),
                rule("snyk", "high", "vulnerable-dependency", "security", "high", "SNYK-JS-AXIOS-7777", "axios has a known high-severity CVE", package_name="axios", package_version="0.21.1", package_manager="npm"),
            ],
        },
        {"backend": {"codeql": "success", "sonarcloud": "success", "gitguardian": "success", "snyk_sca": "success"},
         "frontend": {"codeql": "success", "sonarcloud": "success", "gitguardian": "success", "snyk_sca": "success"},
         "deployed-app": {"zap": "success", "kyverno": "success", "kubearmor": "success"},
         "infrastructure": {"kube-linter": "success", "kubeconform": "success"},
         "terraform": {"checkov": "success", "terraform-validate": "success"}},
        {"backend": {"image_signed": True, "signature_verified": True, "verification_notes": "verified"},
         "frontend": {"image_signed": True, "signature_verified": True, "verification_notes": "verified"}},
    )

    # ── 7. Container-heavy — also never tested with real data ─────────
    build_release_context(
        "container_heavy", "1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa",
        {
            "backend": [
                rule("snyk", "critical", "vulnerable-dependency", "security", "high", "SNYK-DEBIAN12-OPENSSL-1111", "OpenSSL base image package has a critical CVE", package_name="openssl", package_version="3.0.9", package_manager="deb"),
                rule("snyk", "high", "vulnerable-dependency", "security", "high", "SNYK-DEBIAN12-ZLIB-2222", "zlib base image package has a high-severity CVE", package_name="zlib1g", package_version="1.2.13", package_manager="deb"),
                rule("snyk", "medium", "vulnerable-dependency", "security", "high", "SNYK-DEBIAN12-CURL-3333", "curl base image package has a medium-severity CVE", package_name="curl", package_version="7.88.1", package_manager="deb"),
            ],
            "frontend": [
                rule("snyk", "critical", "vulnerable-dependency", "security", "high", "SNYK-DEBIAN12-NODE-4444", "Node.js base image package has a critical CVE", package_name="nodejs", package_version="18.16.0", package_manager="deb"),
                rule("snyk", "high", "vulnerable-dependency", "security", "high", "SNYK-DEBIAN12-EXPAT-5555", "expat base image package has a high-severity CVE", package_name="expat", package_version="2.5.0", package_manager="deb"),
            ],
        },
        {"backend": {"codeql": "success", "sonarcloud": "success", "gitguardian": "success", "snyk_sca": "success"},
         "frontend": {"codeql": "success", "sonarcloud": "success", "gitguardian": "success", "snyk_sca": "success"},
         "deployed-app": {"zap": "success", "kyverno": "success", "kubearmor": "success"},
         "infrastructure": {"kube-linter": "success", "kubeconform": "success"},
         "terraform": {"checkov": "success", "terraform-validate": "success"}},
        {"backend": {"image_signed": True, "signature_verified": True, "verification_notes": "verified"},
         "frontend": {"image_signed": True, "signature_verified": True, "verification_notes": "verified"}},
    )

    # ── 8. Mixed-domain — deliberate cross-domain correlation patterns ─
    build_release_context(
        "mixed_domain", "2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb",
        {
            "terraform": [
                rule("checkov", "high", "workload-identity-disabled", "security", "high", "CKV_GCP_69", "Workload Identity disabled on GKE cluster"),
                rule("checkov", "critical", "excessive-iam-privilege", "security", "high", "CKV_GCP_117", "Project Owner role granted to Compute Engine default service account"),
            ],
            "deployed-app": [
                # Deliberately correlates with the two terraform findings above:
                # disabled Workload Identity + excessive IAM + live token access = one story across two domains
                rule("kubearmor", "high", "unauthorized-file-access", "security", "high", "ksp-audit-serviceaccount-token-access", "Pod accessed the GCP metadata server's service-account token endpoint"),
                rule("kyverno", "medium", "missing-seccomp-profile", "security", "high", "restrict-seccomp-strict", "No seccomp profile set"),
            ],
            "backend": [
                # Deliberately correlates: same package+version, two different CVEs = one upgrade fixes both
                rule("snyk", "critical", "vulnerable-dependency", "security", "high", "SNYK-PYTHON-CRYPTOGRAPHY-1111", "cryptography has a known critical CVE", package_name="cryptography", package_version="38.0.0", package_manager="pip"),
                rule("snyk", "high", "vulnerable-dependency", "security", "high", "SNYK-PYTHON-CRYPTOGRAPHY-2222", "cryptography has a second, separate known CVE at the same version", package_name="cryptography", package_version="38.0.0", package_manager="pip"),
                rule("snyk", "medium", "vulnerable-dependency", "security", "high", "SNYK-DEBIAN12-OPENSSL-3333", "OpenSSL base image package has a medium-severity CVE", package_name="openssl", package_version="3.0.9", package_manager="deb"),
            ],
            "frontend": [
                rule("codeql", "warning", "xss", "security", "medium", "js/xss-through-dom", "Potential DOM-based XSS via innerHTML"),
            ],
        },
        {"backend": {"codeql": "success", "sonarcloud": "success", "gitguardian": "success", "snyk_sca": "success"},
         "frontend": {"codeql": "success", "sonarcloud": "success", "gitguardian": "success", "snyk_sca": "success"},
         "deployed-app": {"zap": "success", "kyverno": "success", "kubearmor": "success"},
         "infrastructure": {"kube-linter": "success", "kubeconform": "success"},
         "terraform": {"checkov": "success", "terraform-validate": "success"}},
        {"backend": {"image_signed": "unknown", "signature_verified": False, "verification_notes": "MANIFEST_UNKNOWN"},
         "frontend": {"image_signed": True, "signature_verified": True, "verification_notes": "verified"}},
    )


if __name__ == "__main__":
    main()
