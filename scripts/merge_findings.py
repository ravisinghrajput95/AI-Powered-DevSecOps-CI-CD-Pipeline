#!/usr/bin/env python3
"""
Merges multiple already-normalized findings JSON files (each a list of
{tool, severity, rule_id, message, file, start_line, end_line}) into one
combined output, for AI agent consumption.

Usage:
    merge_findings.py <output.json> <input1.json> [input2.json ...]
"""
import json
import sys


def main():
    if len(sys.argv) < 3:
        print("Usage: merge_findings.py <output.json> <input1.json> [input2.json ...]", file=sys.stderr)
        sys.exit(1)

    output_path = sys.argv[1]
    input_paths = sys.argv[2:]

    combined = []
    for path in input_paths:
        try:
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, list):
                combined.extend(data)
            else:
                print(f"WARNING: {path} did not contain a JSON list, skipping.", file=sys.stderr)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"WARNING: could not read {path}: {e}", file=sys.stderr)

    with open(output_path, "w") as f:
        json.dump(combined, f, indent=2)

    by_tool = {}
    for finding in combined:
        tool = finding.get("tool", "unknown")
        by_tool[tool] = by_tool.get(tool, 0) + 1

    print(f"Merged {len(combined)} total findings -> {output_path}")
    for tool, count in sorted(by_tool.items()):
        print(f"  {tool}: {count}")


if __name__ == "__main__":
    main()
