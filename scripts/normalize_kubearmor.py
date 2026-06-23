#!/usr/bin/env python3
"""
Normalizes KubeArmor's live alert capture (`karmor logs --json
--logFilter=policy --logPath=<file>`, run for a bounded duration against
the real cloudcart-dev cluster) into the shared schema:
{tool, severity, category, type, rule_id, message, file, line, confidence, recommendation}

VERIFIED SCHEMA (confirmed via KubeArmor's own published Alert protobuf
definition and multiple real example alerts across 2021-2026 docs/blog
posts, all consistent):
{
  "Timestamp": 1639803960,
  "UpdatedTime": "2021-12-18T05:06:00.077564Z",
  "ClusterName": "Default",
  "HostName": "...",
  "NamespaceName": "cloudcart",
  "PodName": "...",
  "ContainerName": "...",
  "PolicyName": "ksp-group-1-proc-path-block",
  "Severity": "5",              // native 1-10 scale, set by the policy author
  "Tags": "...",
  "Message": "...",             // optional, from the policy's own `message:` field
  "Type": "MatchedPolicy",      // or "MatchedHostPolicy", "SystemEvent", etc.
  "Source": "/bin/bash",        // the process that triggered the event
  "Operation": "Process",       // Process | File | Network | Syscall
  "Resource": "/bin/sleep 1",   // the target of the operation
  "Action": "Block",            // Allow | Audit | Block (the POLICY's configured action)
  "Result": "Permission denied" // or "Passed" for Audit-mode violations that were logged, not blocked
}
karmor logs is a STREAMING tool with no persistent history — each line of
--logPath output is presumed to be one JSON object (NDJSON), not a single
JSON array, since the file is appended to live rather than written once at
the end. UNVERIFIED against a real capture (same caveat as
normalize_kyverno.py originally had) — if a real run shows something
different (e.g. an actual JSON array, or extra non-JSON status lines mixed
in), fix this against that real output and update this note.

FUNDAMENTALLY DIFFERENT NORMALIZER SHAPE from kube-linter/checkov/kyverno:
those three have a FIXED, fully-known catalog of checks, so a direct
check-id/(policy,rule) -> (severity, category) lookup table is reliable and
complete. KubeArmor's PolicyName is whatever arbitrary KubeArmorPolicy/
KubeArmorHostPolicy someone has deployed on the live cluster — open-ended
and unknowable in advance. So this normalizer instead uses OPERATION_TO_
CATEGORY, keyed on the small, fixed vocabulary KubeArmor itself defines
for the `Operation` field (Process/File/Network/Syscall) — conceptually
the same kind of pattern-based classification CodeQL/SonarCloud/
GitGuardian/Snyk/ZAP already use via classify_finding.py's CATEGORY_RULES,
just keyed on a structured field instead of regex over free text, since
Operation is already a clean enum rather than something needing pattern
matching.

SEVERITY: unlike kube-linter/checkov (no native severity at all) or
Kyverno (native severity present but uniformly "medium", unusable),
KubeArmor's native Severity field is a genuinely usable 1-10 scale set by
whoever wrote the policy. SEVERITY_BANDS below maps it into this
pipeline's 5-tier scale — own informed banding decision, not anything
KubeArmor's docs prescribe, since KubeArmor doesn't define what the 1-10
numbers mean beyond "the policy author's own judgment."

FINDING CRITERION: only entries where Type is "MatchedPolicy" or
"MatchedHostPolicy" become findings — that's KubeArmor's own signal that
some policy rule actually matched, regardless of whether Action ended up
Block (denied) or Audit (logged but passed through) — both are real,
actionable signals, matching every other tool in this pipeline's "report-
only is still a finding" treatment. Other Types (e.g. "SystemEvent",
general telemetry) are not findings — though --logFilter=policy in the
capture command should already exclude most of those; this re-checks
Type defensively rather than trusting the flag alone, same lesson as
checking summary.parsing_errors explicitly for checkov.

Usage:
    normalize_kubearmor.py <output.json> <kubearmor_logs.json>
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from classify_finding import TYPE_BY_CATEGORY, DEFAULT_TYPE, classify_recommendation

OPERATION_TO_CATEGORY = {
    "Process": "unauthorized-process-execution",
    "File": "unauthorized-file-access",
    "Network": "unauthorized-network-activity",
    "Syscall": "unauthorized-syscall",
}

# Own informed banding of KubeArmor's native 1-10 severity scale into this
# pipeline's 5-tier scale — see SEVERITY note in the docstring above.
SEVERITY_BANDS = [
    (8, "critical"),
    (6, "high"),
    (3, "medium"),
    (1, "low"),
]


def _band_severity(raw_severity):
    try:
        val = int(str(raw_severity).strip())
    except (TypeError, ValueError):
        return "medium"  # no native severity set on the policy — fail-safe default
    for threshold, band in SEVERITY_BANDS:
        if val >= threshold:
            return band
    return "low"


def _parse_lines(report_text):
    """NDJSON parsing — one JSON object per non-blank line, skipping any
    non-JSON status/connection lines defensively rather than crashing the
    whole normalize run over one bad line (same philosophy as every other
    normalizer's try/except around individual records)."""
    events = []
    for line in report_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            print(f"WARNING: skipping non-JSON line in kubearmor capture: {line[:120]!r}", file=sys.stderr)
    return events


def normalize_report(report_text):
    findings = []

    # Defensive: also handle the case where the file IS a single JSON
    # array or object after all, despite the NDJSON assumption above.
    stripped = report_text.strip()
    if stripped.startswith("["):
        try:
            events = json.loads(stripped)
        except json.JSONDecodeError:
            events = _parse_lines(report_text)
    elif stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            events = obj if isinstance(obj, list) else [obj]
        except json.JSONDecodeError:
            events = _parse_lines(report_text)
    else:
        events = _parse_lines(report_text)

    for e in events:
        if not isinstance(e, dict):
            continue
        event_type = e.get("Type", "")
        if event_type not in ("MatchedPolicy", "MatchedHostPolicy"):
            continue

        operation = e.get("Operation", "unknown")
        category = OPERATION_TO_CATEGORY.get(operation)
        if category is None:
            print(
                f"WARNING: unmatched kubearmor Operation {operation!r} "
                f"(PolicyName: {e.get('PolicyName')!r}) — add it to OPERATION_TO_CATEGORY "
                f"in normalize_kubearmor.py.",
                file=sys.stderr,
            )
            category = "uncategorized"

        severity = _band_severity(e.get("Severity"))
        type_ = TYPE_BY_CATEGORY.get(category, DEFAULT_TYPE)
        recommendation = classify_recommendation(category)

        pod_name = e.get("PodName") or e.get("HostName") or "unknown"
        namespace = e.get("NamespaceName", "")
        file_field = f"{namespace}/{pod_name}" if namespace else pod_name

        action = e.get("Action", "")
        result = e.get("Result", "")
        message = e.get("Message") or f"{e.get('Source', 'unknown')} -> {e.get('Resource', 'unknown')}"
        message = f"[{action}/{result}] {message} (policy: {e.get('PolicyName', 'unknown')})"

        findings.append({
            "tool": "kubearmor",
            "severity": severity,
            "category": category,
            "type": type_,
            "rule_id": e.get("PolicyName", "unknown"),
            "message": message,
            "file": file_field,
            "line": None,
            "confidence": "high",  # direct eBPF/LSM kernel-level observation, not a heuristic guess
            "recommendation": recommendation,
        })

    return findings


def main():
    if len(sys.argv) != 3:
        print("Usage: normalize_kubearmor.py <output.json> <kubearmor_logs.json>", file=sys.stderr)
        sys.exit(1)

    output_path = sys.argv[1]
    report_path = sys.argv[2]

    try:
        with open(report_path) as f:
            report_text = f.read()
    except FileNotFoundError as e:
        print(f"WARNING: could not read {report_path}: {e}", file=sys.stderr)
        report_text = ""

    findings = normalize_report(report_text)

    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"Normalized {len(findings)} kubearmor findings -> {output_path}")


if __name__ == "__main__":
    main()