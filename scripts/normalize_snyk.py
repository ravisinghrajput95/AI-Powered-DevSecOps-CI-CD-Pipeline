#!/usr/bin/env python3
"""
Normalizes Snyk's native CLI JSON output — from EITHER `snyk container test`
or `snyk test` (Snyk Open Source / SCA, run against manifests like
requirements.txt or package-lock.json) — into the shared schema:
{tool, severity, category, type, rule_id, message, file, line, confidence,
recommendation, package_name, package_version}

Both commands share the same vulnerabilities[] JSON shape, so one
normalizer covers both — the difference between "this is a container
finding" and "this is an SCA finding" is which workflow/job ran the scan,
not anything structural in the output itself. tool stays "snyk" for both
deliberately, not split into separate tool names: the actual cross-domain
correlation goal (the same vulnerable package showing up in both a
manifest and the built image) depends on `package_name`/`package_version`
being comparable across both, not on hiding that overlap behind different
tool labels.

NOTE: this parses Snyk's *native* JSON format, not SARIF. Native JSON was
chosen over `--sarif-file-output` because it gives structured fields
(packageName, version, severity, fixedIn, CVE identifiers) directly,
rather than requiring regex extraction from a free-text SARIF message —
and because the SARIF output path proved unreliable when generated via
the snyk/actions/docker wrapper action.

VERIFIED SCHEMA (per Snyk CLI docs, confirmed 2026-06-21):
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
  "dependencyCount": 72,
  ...
}
A scan with zero findings still produces this structure with an empty
"vulnerabilities" list (or "ok": true) — that is a normal clean result,
not a parsing failure.

LICENSE FINDINGS (Snyk Open Source / `snyk test` only — container scans
don't carry license info): the exact discriminator field isn't fully
confirmed from documentation alone (some sources show a `type: "license"`
field on the vulnerability entry, others only confirm a `license` field
appears on license-type entries without showing the discriminator
explicitly) — this checks for EITHER signal, so it doesn't matter which
one a given Snyk version actually emits. Unvalidated against real output;
check stderr warnings once a real `snyk test` run exists.

If Snyk's test command is run against multiple targets in one invocation,
the CLI emits a JSON array of objects matching the shape above instead of
a single object — both are handled here.

NOTE: classify_finding.py's CATEGORY_RULES "vulnerable-dependency" and
"license-risk" patterns have not yet been validated against a real Snyk
SCA run (no real output was available when this was written). Check
stderr for "unmatched rule_id" warnings once real data exists, same as
was done for the other tools.

Usage:
    normalize_snyk.py <output.json> <snyk_json_file>
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from classify_finding import classify, classify_recommendation


def normalize_report(report):
    """Extract normalized findings from a single Snyk JSON report (container
    or SCA/manifest test — same shape either way)."""
    findings = []

    for vuln in report.get("vulnerabilities", []):
        rule_id = vuln.get("id", "unknown")
        severity = vuln.get("severity", "unknown")
        title = vuln.get("title", "")
        package_name = vuln.get("packageName")
        package_version = vuln.get("version")

        # License findings only ever come from `snyk test` (Open Source/SCA),
        # never from container scans. Checking both possible signals since
        # documentation wasn't fully consistent on which one Snyk emits.
        is_license_issue = vuln.get("type") == "license" or bool(vuln.get("license"))

        if is_license_issue:
            license_name = vuln.get("license", "unknown license")
            message = f"{package_name}@{package_version} uses license: {license_name}" if package_name else f"License issue: {license_name}"
            category = "license-risk"
            type_ = "security"
            confidence = "high"  # Snyk's own license-policy match, not a heuristic
            recommendation = classify_recommendation(category)
        else:
            cves = vuln.get("identifiers", {}).get("CVE", [])
            message = f"{title} ({', '.join(cves)})" if cves else title
            category, type_, confidence, recommendation = classify("snyk", severity, rule_id, message)

            fixed_in = vuln.get("fixedIn", [])
            if fixed_in:
                recommendation = f"{recommendation} Fixed in: {', '.join(fixed_in)}."

        from_chain = vuln.get("from", [])
        file_field = " > ".join(from_chain) if from_chain else (package_name or "unknown")

        finding = {
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
        }
        if package_name:
            finding["package_name"] = package_name
        if package_version:
            finding["package_version"] = package_version

        findings.append(finding)

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