#!/usr/bin/env python3
"""
Normalizes a GitGuardian `ggshield secret scan ... --json` report into
the shared schema: {tool, severity, rule_id, message, file, start_line, end_line}

IMPORTANT: ggshield's exact JSON schema has not been verified against live
output as of writing this script. This parser is written defensively with
multiple fallback paths for differently-shaped responses. If it produces
zero findings on a run where findings are known to exist, capture the raw
gitguardian-findings.json from that run and the field-extraction logic
below will need correcting to match the real shape.

Usage:
    normalize_gitguardian.py <output.json> <gitguardian-findings.json>
"""
import json
import sys


def get_first(d, keys, default=None):
    """Return the first present key's value from a dict, trying multiple
    possible key names since the real schema is unverified."""
    for k in keys:
        if isinstance(d, dict) and k in d and d[k] is not None:
            return d[k]
    return default


def normalize_entity(entity):
    """
    Attempt to normalize a single 'entity_with_incidents' style record.
    ggshield's documented structure (per public examples) nests incidents
    under each scanned entity/file, each incident containing one or more
    occurrences with line numbers. This function tries several plausible
    shapes defensively rather than assuming one is correct.
    """
    findings = []

    filename = get_first(entity, ["filename", "path", "file"], "unknown")
    incidents = get_first(entity, ["incidents", "policy_breaks", "matches"], [])

    if not isinstance(incidents, list):
        incidents = [incidents]

    for incident in incidents:
        if not isinstance(incident, dict):
            continue

        rule_id = get_first(
            incident,
            ["policy", "detector_name", "type", "break_type"],
            "secret_detected",
        )
        severity = get_first(incident, ["severity", "validity"], "warning")
        message = get_first(
            incident,
            ["description", "message"],
            f"Potential secret detected: {rule_id}",
        )

        occurrences = get_first(incident, ["occurrences", "matches"], [])
        if not isinstance(occurrences, list) or not occurrences:
            # No line-level detail available — emit one finding for the file
            findings.append({
                "tool": "gitguardian",
                "severity": str(severity),
                "rule_id": str(rule_id),
                "message": str(message),
                "file": filename,
                "start_line": None,
                "end_line": None,
            })
            continue

        for occ in occurrences:
            if not isinstance(occ, dict):
                continue
            line = get_first(occ, ["line_start", "line", "start_line"])
            line_end = get_first(occ, ["line_end", "end_line"], line)
            findings.append({
                "tool": "gitguardian",
                "severity": str(severity),
                "rule_id": str(rule_id),
                "message": str(message),
                "file": filename,
                "start_line": line,
                "end_line": line_end,
            })

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

        if data is not None:
            # Try top-level shapes: a bare list of entities, or a dict
            # with a known wrapper key.
            entities = data if isinstance(data, list) else get_first(
                data, ["entities_with_incidents", "results", "scans"], []
            )
            if not isinstance(entities, list):
                entities = [entities]

            for entity in entities:
                if isinstance(entity, dict):
                    all_findings.extend(normalize_entity(entity))

    with open(output_path, "w") as f:
        json.dump(all_findings, f, indent=2)

    print(f"Normalized {len(all_findings)} GitGuardian findings -> {output_path}")
    if content and content != "[]" and not all_findings:
        print(
            "WARNING: input file was non-empty but 0 findings were extracted. "
            "The GitGuardian JSON schema likely differs from what this script "
            "expects — inspect the raw file and update normalize_gitguardian.py.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
