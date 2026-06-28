#!/usr/bin/env python3
"""
Generates the golden ExecutiveReport fixtures matching each golden
ReleaseContext scenario. Run once, by hand, after build_golden_dataset.py
— same "generate once, commit, never regenerate at test time" reasoning,
see that file's docstring.

Every finding_id cited below was copied directly from running
build_golden_dataset.py's actual output (not invented) — these ARE real,
existing finding_ids for their respective scenario, the same way a real
model response should only ever cite real findings. Deliberately spreads
all four recommendation values across the 8 scenarios (clean=APPROVE,
moderate=APPROVE_WITH_CONDITIONS, container_heavy=MANUAL_REVIEW_REQUIRED,
the rest=DO_NOT_APPROVE) so the golden set itself exercises every enum
value, not just the one every real run so far has happened to produce.

mixed_domain's two cross_domain_correlations are deliberate test cases,
not filler: one genuinely spans two domains (workload-identity-disabled +
excessive-iam-privilege, both infrastructure_security + a kubearmor
runtime_security finding), the other is single-domain but multi-finding
(two cryptography CVEs, same package) — together they exercise both the
"genuinely cross-domain" and "compounding within one domain" cases the
minItems:1 relaxation was specifically about.
"""
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/../../../scripts")
from run_security_analysis import assemble_executive_report, compute_report_id
from executive_report_schema import SCHEMA
import jsonschema

GOLDEN_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = GOLDEN_DIR + "/executive_reports"

# Fixed, not the real assemble_executive_report's datetime.now() — same
# reproducibility reasoning as build_golden_dataset.py. Overridden AFTER
# calling the real function below, rather than changing that function's
# actual production behavior (which correctly should use real timestamps).
FIXED_GENERATED_AT = "2026-01-01T00:00:00+00:00"


def build(scenario_name, ai_output):
    release_context = json.load(open(f"{GOLDEN_DIR}/{scenario_name}.json"))
    report = assemble_executive_report(ai_output, release_context)
    report["generated_at"] = FIXED_GENERATED_AT
    report["report_id"] = compute_report_id(release_context.get("release", {}).get("version", ""), FIXED_GENERATED_AT)
    jsonschema.validate(report, SCHEMA)
    with open(f"{OUTPUT_DIR}/{scenario_name}.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"{scenario_name}: OK, recommendation={report['release_readiness']['recommendation']}")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    build("clean_release", {
        "executive_summary": {"overall_health": "LOW", "deployment_confidence": "HIGH", "dominant_risk_themes": ["Minor missing annotation"], "narrative": "This release has one informational finding and no security-relevant issues. All scans succeeded with no high or critical findings."},
        "cross_domain_correlations": [],
        "top_risks": [],
        "priority_actions": [],
        "release_readiness": {"recommendation": "APPROVE", "confidence": "HIGH", "rationale": "No security findings of any severity. All scans completed successfully across every domain.", "blocking_evidence": [], "conditions": None},
        "assumptions_and_unknowns": [],
    })

    build("moderate_risk_release", {
        "executive_summary": {"overall_health": "MEDIUM", "deployment_confidence": "MEDIUM", "dominant_risk_themes": ["Missing security headers", "Outdated dependency"], "narrative": "This release has a handful of medium and low severity findings spanning application, infrastructure, and runtime domains. None are critical or high severity."},
        "cross_domain_correlations": [],
        "top_risks": [
            {"risk_id": "risk-1", "title": "Outdated requests library", "impact": "Known moderate-severity CVE in a core HTTP library.", "why_it_matters": "Affects every outbound request the backend makes.", "confidence": "HIGH", "supporting_evidence": ["c901f3f49ece"], "recommended_action": "Upgrade requests to the patched version."},
        ],
        "priority_actions": [
            {"action_id": "action-1", "title": "Set Content-Security-Policy and Cache-Control headers", "rationale": "Two related ZAP findings resolved by the same reverse-proxy config change.", "expected_risk_reduction": "Removes the missing-header findings entirely.", "dependencies": [], "estimated_complexity": "LOW", "supporting_evidence": ["4009060fb6d5", "8abe2ddb9d74"]},
        ],
        "release_readiness": {"recommendation": "APPROVE_WITH_CONDITIONS", "confidence": "MEDIUM", "rationale": "No high or critical findings, but several medium/low issues should be addressed before or shortly after deployment.", "blocking_evidence": [], "conditions": ["Upgrade requests past the known CVE", "Add the missing security headers"]},
        "assumptions_and_unknowns": [
            {"related_to": "signal_availability.reachability", "impact_on_assessment": "Reachability is not collected; prioritization relies on severity and confidence alone."},
        ],
    })

    build("critical_release", {
        "executive_summary": {"overall_health": "CRITICAL", "deployment_confidence": "LOW", "dominant_risk_themes": ["Excessive IAM privilege", "Live privilege escalation"], "narrative": "This release combines project-level IAM over-privilege with confirmed live privilege-escalation and root execution on running pods. The combination represents a direct path from container compromise to broad GCP access."},
        "cross_domain_correlations": [
            {"correlation_id": "corr-1", "title": "Excessive IAM Privilege Compounds Live Privilege Escalation", "description": "A project-level Owner role is granted to a service account that backs workloads where privilege escalation and root execution are both confirmed enabled live.", "business_impact": "A compromised container can escalate to full project access with no additional barrier.", "confidence": "HIGH", "affected_domains": ["infrastructure_security", "runtime_security"], "supporting_evidence": ["0487801b1fb6", "43213a439b92", "16f9a8df84b3"], "recommended_action": "Remove the Owner role and harden pod securityContexts together — fixing either alone leaves the other half of the path intact."},
        ],
        "top_risks": [
            {"risk_id": "risk-1", "title": "Live privilege escalation and root execution", "impact": "Confirmed by Kyverno on running pods, not a hypothetical misconfiguration.", "why_it_matters": "This is the most direct path to container breakout.", "confidence": "HIGH", "supporting_evidence": ["43213a439b92", "16f9a8df84b3"], "recommended_action": "Set allowPrivilegeEscalation: false and runAsNonRoot: true across all workloads."},
        ],
        "priority_actions": [
            {"action_id": "action-1", "title": "Harden pod securityContexts", "rationale": "Resolves both live Kyverno violations in one Helm values change.", "expected_risk_reduction": "Eliminates the confirmed privilege-escalation and root-execution path.", "dependencies": [], "estimated_complexity": "MEDIUM", "supporting_evidence": ["43213a439b92", "16f9a8df84b3"]},
        ],
        "release_readiness": {"recommendation": "DO_NOT_APPROVE", "confidence": "HIGH", "rationale": "Multiple critical, live, high-confidence findings with a confirmed compounding path between infrastructure IAM and runtime privilege escalation.", "blocking_evidence": ["0487801b1fb6", "57df84a4027d", "43213a439b92", "16f9a8df84b3"], "conditions": None},
        "assumptions_and_unknowns": [
            {"related_to": "scan_status.backend.codeql", "impact_on_assessment": "Application-layer scanning was skipped; code-level risk is entirely unassessed for this release."},
        ],
    })

    build("infrastructure_heavy", {
        "executive_summary": {"overall_health": "CRITICAL", "deployment_confidence": "LOW", "dominant_risk_themes": ["Excessive IAM privilege", "Workload Identity disabled"], "narrative": "This release is dominated by infrastructure misconfigurations: project-level IAM over-privilege, disabled Workload Identity, an open firewall rule, and several lower-severity hardening gaps."},
        "cross_domain_correlations": [],
        "top_risks": [
            {"risk_id": "risk-1", "title": "Project Owner role granted to a service account", "impact": "Broadest possible GCP privilege granted at the project level.", "why_it_matters": "Any workload using this service account inherits full project access.", "confidence": "HIGH", "supporting_evidence": ["0487801b1fb6"], "recommended_action": "Replace with least-privilege predefined roles."},
            {"risk_id": "risk-2", "title": "Workload Identity disabled", "impact": "Pods inherit node-level credentials via the metadata server instead of scoped per-pod identity.", "why_it_matters": "Removes the standard GKE mechanism for limiting blast radius of a compromised pod.", "confidence": "HIGH", "supporting_evidence": ["f1f751c2ee51"], "recommended_action": "Enable Workload Identity on the cluster and node pools."},
        ],
        "priority_actions": [
            {"action_id": "action-1", "title": "Enable Workload Identity and scope IAM to least privilege together", "rationale": "These two findings compound each other; fixing both at once closes the path between them.", "expected_risk_reduction": "Removes the broad-credential-inheritance path entirely.", "dependencies": [], "estimated_complexity": "MEDIUM", "supporting_evidence": ["0487801b1fb6", "f1f751c2ee51"]},
        ],
        "release_readiness": {"recommendation": "DO_NOT_APPROVE", "confidence": "HIGH", "rationale": "Critical IAM over-privilege combined with disabled Workload Identity is an unmitigated, high-confidence finding pair.", "blocking_evidence": ["0487801b1fb6", "f1f751c2ee51"], "conditions": None},
        "assumptions_and_unknowns": [],
    })

    build("runtime_heavy", {
        "executive_summary": {"overall_health": "CRITICAL", "deployment_confidence": "LOW", "dominant_risk_themes": ["Live privilege escalation", "Root execution on running pods"], "narrative": "This release shows confirmed, live policy violations across the deployed runtime surface: privilege escalation, root execution, missing seccomp profiles, and unsigned images, all confirmed by Kyverno and KubeArmor against running workloads."},
        "cross_domain_correlations": [],
        "top_risks": [
            {"risk_id": "risk-1", "title": "Privilege escalation and root execution live on running pods", "impact": "Confirmed live, not a static config check.", "why_it_matters": "This is an active, exploitable condition right now.", "confidence": "HIGH", "supporting_evidence": ["43213a439b92", "16f9a8df84b3"], "recommended_action": "Harden securityContext across all deployed workloads."},
        ],
        "priority_actions": [
            {"action_id": "action-1", "title": "Harden all workload securityContexts in one pass", "rationale": "Resolves privilege-escalation, root-execution, seccomp, and capabilities findings together — they're all the same class of fix.", "expected_risk_reduction": "Eliminates every confirmed live container-hardening violation.", "dependencies": [], "estimated_complexity": "MEDIUM", "supporting_evidence": ["43213a439b92", "16f9a8df84b3", "07c3e8a9e18a", "8b9492be7c39"]},
        ],
        "release_readiness": {"recommendation": "DO_NOT_APPROVE", "confidence": "HIGH", "rationale": "Multiple critical, live runtime violations confirmed by two independent tools (Kyverno and KubeArmor).", "blocking_evidence": ["43213a439b92", "16f9a8df84b3"], "conditions": None},
        "assumptions_and_unknowns": [],
    })

    build("application_heavy", {
        "executive_summary": {"overall_health": "CRITICAL", "deployment_confidence": "LOW", "dominant_risk_themes": ["Live secret in commit history", "Critical SQL injection", "Vulnerable Flask dependency"], "narrative": "This release surfaces a confirmed live secret, a SQL injection vulnerability, and multiple critical/high dependency CVEs across both backend and frontend — the application-security domain this pipeline rarely gets to assess given how often these scans are skipped."},
        "cross_domain_correlations": [],
        "top_risks": [
            {"risk_id": "risk-1", "title": "Live secret confirmed in commit history", "impact": "GitGuardian confirmed this credential is currently valid, not just pattern-matched.", "why_it_matters": "An active credential in git history is immediately exploitable by anyone with repo access.", "confidence": "HIGH", "supporting_evidence": ["d16c1bbff022"], "recommended_action": "Revoke the credential immediately and purge it from git history."},
            {"risk_id": "risk-2", "title": "SQL injection in order routes", "impact": "Unsanitized user input reaches a SQL query.", "why_it_matters": "Direct path to data exfiltration or corruption.", "confidence": "HIGH", "supporting_evidence": ["25ed174a1d1c"], "recommended_action": "Use parameterized queries."},
        ],
        "priority_actions": [
            {"action_id": "action-1", "title": "Revoke and rotate the exposed credential", "rationale": "Highest-impact, lowest-effort fix — a single rotation closes the most urgent exposure.", "expected_risk_reduction": "Eliminates the live-secret risk entirely.", "dependencies": [], "estimated_complexity": "LOW", "supporting_evidence": ["d16c1bbff022"]},
            {"action_id": "action-2", "title": "Upgrade Flask past both known CVEs", "rationale": "Two separate CVEs share the same pinned Flask version — one upgrade resolves both.", "expected_risk_reduction": "Removes both flagged Flask CVEs in one change.", "dependencies": [], "estimated_complexity": "LOW", "supporting_evidence": ["a21dde1a0c94", "a50a5daf8fa4"]},
        ],
        "release_readiness": {"recommendation": "DO_NOT_APPROVE", "confidence": "HIGH", "rationale": "A confirmed live secret plus an unmitigated SQL injection are each independently sufficient to block this release.", "blocking_evidence": ["d16c1bbff022", "25ed174a1d1c"], "conditions": None},
        "assumptions_and_unknowns": [],
    })

    build("container_heavy", {
        "executive_summary": {"overall_health": "HIGH", "deployment_confidence": "MEDIUM", "dominant_risk_themes": ["Outdated base image packages", "Critical OS-layer CVEs"], "narrative": "Both backend and frontend container images carry critical and high-severity CVEs in their base-image OS packages (OpenSSL, Node.js runtime, zlib). These are container-layer findings, distinct from application dependency findings."},
        "cross_domain_correlations": [],
        "top_risks": [
            {"risk_id": "risk-1", "title": "Critical OpenSSL CVE in backend base image", "impact": "A critical, widely-exploited class of vulnerability in the TLS library.", "why_it_matters": "OpenSSL CVEs are frequently weaponized quickly after disclosure.", "confidence": "HIGH", "supporting_evidence": ["3e4f1bdcc5bd"], "recommended_action": "Rebuild on an updated base image."},
            {"risk_id": "risk-2", "title": "Critical Node.js runtime CVE in frontend base image", "impact": "Critical CVE in the JS runtime itself, not application code.", "why_it_matters": "Affects the entire frontend container regardless of application-level fixes.", "confidence": "HIGH", "supporting_evidence": ["8de70bc6a7d4"], "recommended_action": "Rebuild on an updated Node base image."},
        ],
        "priority_actions": [
            {"action_id": "action-1", "title": "Rebuild both images on current base-image tags", "rationale": "Both critical findings and most of the high findings are resolved by a base-image bump, not application code changes.", "expected_risk_reduction": "Resolves all 5 container-layer CVEs in one CI change.", "dependencies": [], "estimated_complexity": "LOW", "supporting_evidence": ["3e4f1bdcc5bd", "8de70bc6a7d4"]},
        ],
        "release_readiness": {"recommendation": "MANUAL_REVIEW_REQUIRED", "confidence": "MEDIUM", "rationale": "Critical container-layer CVEs exist, but the fix (a base-image rebuild) is low-complexity and well-understood — a human should confirm whether to block on this or fast-track the rebuild.", "blocking_evidence": ["3e4f1bdcc5bd", "8de70bc6a7d4"], "conditions": None},
        "assumptions_and_unknowns": [],
    })

    build("mixed_domain", {
        "executive_summary": {"overall_health": "CRITICAL", "deployment_confidence": "LOW", "dominant_risk_themes": ["Workload Identity disabled with excessive IAM", "Cryptography library CVEs"], "narrative": "This release shows a confirmed cross-domain path from disabled Workload Identity and excessive project IAM through to live runtime token access, plus a separate, unrelated pair of CVEs in the same pinned cryptography package."},
        "cross_domain_correlations": [
            {
                "correlation_id": "corr-1", "title": "Workload Identity Disabled + Excessive IAM + Live Token Access",
                "description": "Workload Identity is disabled (infrastructure) and a project-level Owner role is granted (infrastructure) to the service account those nodes inherit. KubeArmor independently confirms, at runtime, a pod actually accessing the GCP metadata server's service-account token endpoint.",
                "business_impact": "A compromised pod can obtain a token with project-level access via the metadata server — confirmed reachable, not theoretical.",
                "confidence": "HIGH", "affected_domains": ["infrastructure_security", "runtime_security"],
                "supporting_evidence": ["f1f751c2ee51", "0487801b1fb6", "9b21cc78c52e"],
                "recommended_action": "Enable Workload Identity and remove the Owner role together — the runtime finding confirms this path is real, not hypothetical.",
            },
            {
                "correlation_id": "corr-2", "title": "Cryptography Package — Two CVEs, One Upgrade",
                "description": "The same pinned cryptography package version has two independently-disclosed CVEs reported separately by Snyk.",
                "business_impact": "Both vulnerabilities are present simultaneously in every backend instance running this pinned version.",
                "confidence": "HIGH", "affected_domains": ["application_security"],
                "supporting_evidence": ["e56d59eca03b", "db5d25cb9447"],
                "recommended_action": "Upgrade cryptography past both CVEs in a single dependency bump.",
            },
        ],
        "top_risks": [
            {"risk_id": "risk-1", "title": "Confirmed path from disabled Workload Identity to live metadata-server token access", "impact": "Live, confirmed runtime evidence of an infrastructure misconfiguration being actively reachable.", "why_it_matters": "This is not a static finding — KubeArmor saw it happen.", "confidence": "HIGH", "supporting_evidence": ["f1f751c2ee51", "9b21cc78c52e"], "recommended_action": "See corr-1."},
        ],
        "priority_actions": [
            {"action_id": "action-1", "title": "Enable Workload Identity and scope IAM together", "rationale": "Addresses the highest-confidence finding in this release.", "expected_risk_reduction": "Closes the confirmed token-access path.", "dependencies": [], "estimated_complexity": "MEDIUM", "supporting_evidence": ["f1f751c2ee51", "0487801b1fb6"]},
            {"action_id": "action-2", "title": "Upgrade cryptography", "rationale": "One dependency bump resolves two CVEs.", "expected_risk_reduction": "Removes both cryptography CVEs.", "dependencies": [], "estimated_complexity": "LOW", "supporting_evidence": ["e56d59eca03b", "db5d25cb9447"]},
        ],
        "release_readiness": {"recommendation": "DO_NOT_APPROVE", "confidence": "HIGH", "rationale": "A confirmed, live cross-domain privilege-escalation path is independently sufficient to block this release.", "blocking_evidence": ["f1f751c2ee51", "0487801b1fb6", "9b21cc78c52e"], "conditions": None},
        "assumptions_and_unknowns": [],
    })


if __name__ == "__main__":
    main()
