#!/usr/bin/env python3
"""
Normalizes one or more CodeQL SARIF files into the shared schema:
{tool, severity, category, rule_id, message, file, line, confidence, recommendation}

Usage:
    normalize_codeql.py <output.json> <sarif_file_1> [sarif_file_2 ...]
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from normalizer_common import parse_args, load_report, write_findings
from classify_finding import classify, build_line_field


def normalize_sarif(sarif_path):
    """Extract normalized findings from a single SARIF file."""
    findings = []
    try:
        with open(sarif_path) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"WARNING: could not read {sarif_path}: {e}", file=sys.stderr)
        return findings

    for run in data.get("runs", []):
        for result in run.get("results", []):
            message = result.get("message", {}).get("text", "")
            rule_id = result.get("ruleId", "unknown")
            level = result.get("level", "note")

            locations = result.get("locations", [])
            file_path = "unknown"
            start_line = None
            end_line = None
            if locations:
                phys = locations[0].get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri", "unknown")
                region = phys.get("region", {})
                start_line = region.get("startLine")
                end_line = region.get("endLine")

            category, type_, confidence, recommendation = classify("codeql", level, rule_id, message)

            findings.append({
                "tool": "codeql",
                "severity": level,
                "category": category,
                "type": type_,
                "rule_id": rule_id,
                "message": message,
                "file": file_path,
                "line": build_line_field(start_line, end_line),
                "confidence": confidence,
                "recommendation": recommendation,
            })

    return findings


def main():
    args = parse_args("normalize_codeql.py", ["<output.json>", "<sarif_file>..."])
    output_path, sarif_paths = args[0], args[1:]
    findings = [f for p in sarif_paths for f in normalize_sarif(p)]
    write_findings(output_path, findings, "CodeQL")


if __name__ == "__main__":
    main()
