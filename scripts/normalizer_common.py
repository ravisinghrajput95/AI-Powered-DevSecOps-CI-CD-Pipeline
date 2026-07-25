#!/usr/bin/env python3
"""
Shared CLI plumbing for the normalize_*.py scripts.

Every normalizer repeated the same ~20-line main(): check argv length, open
the report inside a try/except that degrades to an empty result, call the
tool-specific parser, dump JSON, print a count. Nine near-identical copies
meant nine places to change error handling, and they had already drifted —
some caught FileNotFoundError only, some also caught JSONDecodeError, and
the usage strings disagreed about argument order.

This module holds only the parts that are genuinely identical. The parsing
itself stays in each normalizer, because that is where the real per-tool
knowledge lives (see each script's docstring for its verified schema).

Deliberately NOT argparse: these are invoked from workflow YAML as
`normalize_x.py <output> <input>`, and switching to flags would break every
call site for no benefit. What was worth fixing is the duplication and the
inconsistent failure behaviour, not the interface.

Import errors raise rather than sys.exit() — these modules get imported by
tests and by the golden-dataset builders, and SystemExit during import
crashes an importer's collection instead of surfacing as a catchable error.
"""
import json
import sys


def parse_args(script_name, arg_names, argv=None):
    """Positional-argument parsing with a consistent usage message.

    arg_names describes the expected arguments; a trailing name ending in
    '...' means "one or more" (normalize_codeql takes multiple SARIF files)
    and a name wrapped in [] is optional (normalize_sbom's component label).

    Returns the argument list (excluding argv[0]). Exits 1 with the usage
    string when the count is wrong — the same behaviour every normalizer
    already had, just stated once.
    """
    argv = sys.argv if argv is None else argv
    args = argv[1:]

    variadic = bool(arg_names) and arg_names[-1].endswith("...")
    optional = sum(1 for a in arg_names if a.startswith("["))
    required = len(arg_names) - optional

    ok = len(args) >= required if (variadic or optional) else len(args) == required
    if not ok:
        usage = " ".join(arg_names)
        print(f"Usage: {script_name} {usage}", file=sys.stderr)
        sys.exit(1)
    return args


def load_report(path, default=None, mode="json"):
    """Read a tool's raw report, degrading to `default` with a warning.

    A missing or malformed report is normal, not exceptional: a scan may
    have been skipped, or the tool may have failed before writing anything.
    The pipeline's contract is that a normalizer always produces a valid
    output file, so downstream consumers get an empty finding list rather
    than a crash.

    NOTE this is deliberately quiet about WHY the report is unusable — that
    signal belongs in the workflow's scan-status recording, which captures
    the tool's real exit code. A normalizer cannot tell "clean scan" from
    "scanner never ran"; only the exit code can, and conflating the two here
    is what let expired credentials look like clean results.

    mode="json" parses and returns an object; mode="text" returns the raw
    string (normalize_kubearmor consumes a JSON-lines stream, not a document).
    """
    if default is None:
        default = {} if mode == "json" else ""
    try:
        with open(path) as f:
            return json.load(f) if mode == "json" else f.read()
    except FileNotFoundError:
        print(f"WARNING: could not read {path}: file not found", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"WARNING: could not parse {path} as JSON: {e}", file=sys.stderr)
    return default


def write_findings(output_path, findings, tool_label):
    """Write the normalized findings and report the count.

    Always writes, including for an empty list — downstream steps expect the
    file to exist regardless of outcome.
    """
    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"Normalized {len(findings)} {tool_label} findings -> {output_path}")
    return findings
