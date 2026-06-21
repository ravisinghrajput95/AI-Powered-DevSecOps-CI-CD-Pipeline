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
    by_category = {}
    uncategorized_findings = []
    for finding in combined:
        tool = finding.get("tool", "unknown")
        by_tool[tool] = by_tool.get(tool, 0) + 1
        category = finding.get("category", "unknown")
        by_category[category] = by_category.get(category, 0) + 1
        if category == "uncategorized":
            uncategorized_findings.append(finding)

    print(f"Merged {len(combined)} total findings -> {output_path}")
    print("\nBy tool:")
    for tool, count in sorted(by_tool.items()):
        print(f"  {tool}: {count}")
    print("\nBy category:")
    for category, count in sorted(by_category.items(), key=lambda x: -x[1]):
        print(f"  {category}: {count}")

    if uncategorized_findings:
        print(
            f"\n*** WARNING: {len(uncategorized_findings)} finding(s) fell back to "
            f"'uncategorized'. Since this codebase's rule_id surface is fixed, this "
            f"likely means classify_finding.py's CATEGORY_RULES needs a new pattern, "
            f"not that genuinely new code appeared. Details: ***",
            file=sys.stderr,
        )
        for f in uncategorized_findings:
            print(f"  - tool={f.get('tool')} rule_id={f.get('rule_id')!r} file={f.get('file')}", file=sys.stderr)


if __name__ == "__main__":
    main()
