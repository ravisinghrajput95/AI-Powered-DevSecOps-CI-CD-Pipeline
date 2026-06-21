#!/usr/bin/env python3
"""
Normalizes Snyk's native CLI JSON output (produced via
`snyk container test --json-file-output=...`) into the shared schema:
{tool, severity, category, type, rule_id, message, file, line, confidence, recommendation}

NOTE: this parses Snyk's *native* JSON format, not SARIF. Native JSON was
chosen over `--sarif-file-output` because it gives structured fields
(packageName, version, severity, fixedIn, CVE identifiers) directly,
rather than requiring regex extraction from a free-text SARIF message —
and because the SARIF output path proved unreliable when generated via
the snyk/actions/docker wrapper action.

VERIFIED SCHEMA (per Snyk CLI container-test docs, confirmed 2026-06-21):
{
  "vulnerabilities": [
    {
      "id": "SNYK-DEBIAN12-OPENSSL-7654321",
      "title": "...",
      "severity": "low" | "medium" | "high" | "critical",
      "packageName": "openssl",
      "version": "3.0.13-1",
      "fixedIn": ["3.0.14-r2"],
      "identifiers": {"CVE": ["CVE-2024-12345"], ...},
      "from": ["image@tag", "openssl@3.0.13-1"],
      ...
    }
  ],
  "ok": false,
  "packageManager": "deb",
  ...
}
A scan with zero findings still produces this structure with an empty
"vulnerabilities" list (or "ok": true) — that is a normal clean result,
not a parsing failure.

If Snyk's `container test` is run against multiple targets in one
invocation, the CLI emits a JSON array of objects matching the shape
above instead of a single object — both are handled here.

NOTE: classify_finding.py's CATEGORY_RULES "vulnerable-dependency" pattern
has not yet been validated against a real Snyk run (no real output was
available when this was written). Check stderr for "unmatched rule_id"
warnings once real data exists, same as was done for the other tools.

Usage:
    normalize_snyk.py <output.json> <snyk_json_file>
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from classify_finding import classify


def normalize_report(report):
    """Extract normalized findings from a single Snyk container-test JSON report."""
    findings = []

    for vuln in report.get("vulnerabilities", []):
        rule_id = vuln.get("id", "unknown")
        severity = vuln.get("severity", "unknown")
        title = vuln.get("title", "")

        cves = vuln.get("identifiers", {}).get("CVE", [])
        message = f"{title} ({', '.join(cves)})" if cves else title

        from_chain = vuln.get("from", [])
        file_field = " > ".join(from_chain) if from_chain else vuln.get("packageName", "unknown")

        category, type_, confidence, recommendation = classify("snyk", severity, rule_id, message)

        fixed_in = vuln.get("fixedIn", [])
        if fixed_in:
            recommendation = f"{recommendation} Fixed in: {', '.join(fixed_in)}."

        findings.append({
            "tool": "snyk",
            "severity": severity,
            "category": category,
            "type": type_,
            "rule_id": rule_id,
            "message": message,
            "file": file_field,
            "line": None,
            "confidence": confidence,
            "recommendation": recommendation,
        })

    return findings


def normalize_file(json_path):
    findings = []
    try:
        with open(json_path) as f:
            content = f.read().strip()
    except FileNotFoundError:
        print(f"WARNING: {json_path} not found — Snyk scan may not have produced a report.", file=sys.stderr)
        return findings

    if not content:
        print(f"WARNING: {json_path} is empty.", file=sys.stderr)
        return findings

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        print(f"WARNING: could not parse {json_path} as JSON: {e}", file=sys.stderr)
        return findings

    if isinstance(data, list):
        for report in data:
            findings.extend(normalize_report(report))
    elif isinstance(data, dict):
        findings.extend(normalize_report(data))
    else:
        print(f"WARNING: unexpected top-level JSON type in {json_path}: {type(data)}", file=sys.stderr)

    return findings


def main():
    if len(sys.argv) != 3:
        print("Usage: normalize_snyk.py <output.json> <snyk_json_file>", file=sys.stderr)
        sys.exit(1)

    output_path = sys.argv[1]
    input_path = sys.argv[2]

    all_findings = normalize_file(input_path)

    with open(output_path, "w") as f:
        json.dump(all_findings, f, indent=2)

    print(f"Normalized {len(all_findings)} Snyk findings -> {output_path}")


if __name__ == "__main__":
    main()