#!/usr/bin/env python3
"""
Normalizes a GitGuardian `ggshield secret scan ... --json` report into
the shared schema:
{tool, severity, category, rule_id, message, file, line, confidence, recommendation}

VERIFIED SCHEMA (confirmed against real ggshield output on 2026-06-20):
{
  "scans": [
    {
      "id": "<commit sha>",
      "entities_with_incidents": [
        {
          "filename": "path/to/file",
          "incidents": [
            {
              "type": "Username Password" | "Stripe Keys" | "Generic Password" | ...,
              "occurrences": [
                {"type": "username", "line_start": 14, "line_end": 14}
              ],
              "validity": "no_checker" | "invalid" | "valid" | ...,
              "incident_url": "https://dashboard.gitguardian.com/...",
              "ignore_reason": null | {"kind": "...", "detail": "..."}
            }
          ]
        }
      ]
    }
  ]
}

Usage:
    normalize_gitguardian.py <output.json> <gitguardian-findings.json>
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from classify_finding import classify, build_line_field


def normalize_incident(incident, filename):
    """Emit one normalized finding per occurrence within an incident."""
    findings = []

    incident_type = incident.get("type", "secret_detected")
    validity = incident.get("validity", "unknown")
    incident_url = incident.get("incident_url", "")
    ignore_reason = incident.get("ignore_reason")

    def build_message(occ_type=None):
        msg = f"{incident_type}"
        if occ_type:
            msg += f" ({occ_type})"
        msg += f" detected (validity: {validity})"
        if incident_url:
            msg += f" — {incident_url}"
        if ignore_reason:
            msg += f" [ignored: {ignore_reason.get('detail', ignore_reason.get('kind', ''))}]"
        return msg

    occurrences = incident.get("occurrences", [])
    if not occurrences:
        message = build_message()
        category, confidence, recommendation = classify("gitguardian", validity, incident_type, message)
        findings.append({
            "tool": "gitguardian",
            "severity": validity,
            "category": category,
            "rule_id": incident_type,
            "message": message,
            "file": filename,
            "line": None,
            "confidence": confidence,
            "recommendation": recommendation,
        })
        return findings

    for occ in occurrences:
        occ_type = occ.get("type", "")
        message = build_message(occ_type)
        category, confidence, recommendation = classify("gitguardian", validity, incident_type, message)

        findings.append({
            "tool": "gitguardian",
            "severity": validity,
            "category": category,
            "rule_id": incident_type,
            "message": message,
            "file": filename,
            "line": build_line_field(occ.get("line_start"), occ.get("line_end")),
            "confidence": confidence,
            "recommendation": recommendation,
        })

    return findings


def normalize_entity(entity):
    """One entity = one file within one commit scan."""
    findings = []
    filename = entity.get("filename", "unknown")
    incidents = entity.get("incidents", [])

    for incident in incidents:
        findings.extend(normalize_incident(incident, filename))

    return findings


def main():
    if len(sys.argv) != 3:
        print("Usage: normalize_gitguardian.py <output.json> <gitguardian-findings.json>", file=sys.stderr)
        sys.exit(1)

    output_path = sys.argv[1]
    input_path = sys.argv[2]

    all_findings = []
    try:
        with open(input_path) as f:
            content = f.read().strip()
    except FileNotFoundError:
        content = ""

    if content and content != "[]":
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            print(f"WARNING: could not parse {input_path} as JSON: {e}", file=sys.stderr)
            data = None

        if isinstance(data, dict):
            scans = data.get("scans", [])
            for scan in scans:
                entities = scan.get("entities_with_incidents", [])
                for entity in entities:
                    all_findings.extend(normalize_entity(entity))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "entities_with_incidents" in item:
                    for entity in item["entities_with_incidents"]:
                        all_findings.extend(normalize_entity(entity))
                elif isinstance(item, dict) and "filename" in item:
                    all_findings.extend(normalize_entity(item))

    with open(output_path, "w") as f:
        json.dump(all_findings, f, indent=2)

    print(f"Normalized {len(all_findings)} GitGuardian findings -> {output_path}")
    if content and content != "[]" and not all_findings:
        print(
            "WARNING: input file was non-empty but 0 findings were extracted. "
            "The GitGuardian JSON schema may have changed.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
