#!/usr/bin/env python3
"""
Normalizes a GitGuardian `ggshield secret scan ... --json` report into
the shared schema: {tool, severity, rule_id, message, file, start_line, end_line}

VERIFIED SCHEMA (confirmed against real ggshield output on 2026-06-20):
{
  "id": "<scan id>",
  "type": "commit-range",
  "scans": [
    {
      "id": "<commit sha>",
      "type": "commit",
      "entities_with_incidents": [
        {
          "mode": "NEW" | "MODIFY" | "DELETE" | "RENAME",
          "filename": "path/to/file",
          "incidents": [
            {
              "policy": "Secrets detection",
              "type": "Username Password" | "Stripe Keys" | "Generic Password" | ...,
              "occurrences": [
                {"type": "username", "line_start": 14, "line_end": 14, "match": "cl*****rt"},
                {"type": "password", "line_start": 15, "line_end": 15, "match": "cl********23"}
              ],
              "validity": "no_checker" | "invalid" | "valid" | ...,
              "ignore_sha": "<sha>",
              "incident_url": "https://dashboard.gitguardian.com/...",
              "known_secret": true,
              "ignore_reason": null | {"kind": "...", "detail": "..."}
            }
          ],
          "total_incidents": 1,
          "total_occurrences": 1
        }
      ],
      "extra_info": {"author": "...", "email": "...", "date": "..."},
      "total_incidents": 1,
      "total_occurrences": 1
    }
  ],
  "total_incidents": 6,
  "total_occurrences": 6,
  "secrets_engine_version": "2.165.0"
}

Note: each "incident" can have multiple "occurrences" (e.g. a Username
Password incident has one occurrence for the username and one for the
password, each with its own line number) — these are emitted as separate
normalized findings since they have distinct line numbers.

Usage:
    normalize_gitguardian.py <output.json> <gitguardian-findings.json>
"""
import json
import sys


def normalize_incident(incident, filename):
    """Emit one normalized finding per occurrence within an incident."""
    findings = []

    incident_type = incident.get("type", "secret_detected")
    validity = incident.get("validity", "unknown")
    incident_url = incident.get("incident_url", "")
    ignore_reason = incident.get("ignore_reason")

    base_message = f"{incident_type} detected (validity: {validity})"
    if incident_url:
        base_message += f" — {incident_url}"
    if ignore_reason:
        base_message += f" [ignored: {ignore_reason.get('detail', ignore_reason.get('kind', ''))}]"

    occurrences = incident.get("occurrences", [])
    if not occurrences:
        # Incident with no occurrence detail — still emit one finding
        findings.append({
            "tool": "gitguardian",
            "severity": validity,
            "rule_id": incident_type,
            "message": base_message,
            "file": filename,
            "start_line": None,
            "end_line": None,
        })
        return findings

    for occ in occurrences:
        occ_type = occ.get("type", "")
        occ_message = base_message
        if occ_type:
            occ_message = f"{incident_type} ({occ_type}) detected (validity: {validity})"
            if incident_url:
                occ_message += f" — {incident_url}"
            if ignore_reason:
                occ_message += f" [ignored: {ignore_reason.get('detail', ignore_reason.get('kind', ''))}]"

        findings.append({
            "tool": "gitguardian",
            "severity": validity,
            "rule_id": incident_type,
            "message": occ_message,
            "file": filename,
            "start_line": occ.get("line_start"),
            "end_line": occ.get("line_end"),
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
            # Fallback for a bare list shape, in case ggshield's output
            # format differs by version/invocation.
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
            "The GitGuardian JSON schema may have changed — inspect the raw "
            "file and update normalize_gitguardian.py.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()