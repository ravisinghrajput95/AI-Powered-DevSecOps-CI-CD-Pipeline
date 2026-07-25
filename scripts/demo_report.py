#!/usr/bin/env python3
"""Render a release report locally from committed fixtures.

Everything the pipeline produces normally requires a GKE cluster, eight
scanner integrations and an ANTHROPIC_API_KEY. That is a high bar for someone
who just wants to see whether the output is any good, so this renders the
same reports from fixtures already in the repository — no cloud, no
credentials, no API spend, no network.

What this does and does not prove:

    proves      the renderers, the schemas, and citation resolution — the
                deterministic half of the system
    not proved  the AI reasoning itself, which is fixed in these fixtures
                rather than generated. For that you need a real run
                (release-readiness.yaml) and an API key.

The distinction matters: this is a rendering demo, not an evaluation harness.

Citation enforcement is graded, and worth stating precisely because it is
easy to overclaim. A malformed finding_id fails the schema and the renderer
refuses to write the file at all. A *well-formed but unresolvable* id renders
successfully and emits a ::warning:: — deliberately, per
run_security_analysis.py's verify_finding_id_references(), which treats it as
a data-quality signal rather than grounds to discard an otherwise-valid
report. So "every citation resolves" is not something this demo proves; what
it proves is that unresolvable ones are always surfaced.

Usage:
    python3 scripts/demo_report.py                    # the real-world report
    python3 scripts/demo_report.py --list
    python3 scripts/demo_report.py --scenario critical_release
    python3 scripts/demo_report.py --all --out-dir /tmp/reports
"""

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GOLDEN = os.path.join(ROOT, "tests", "fixtures", "golden")
REAL = os.path.join(ROOT, "tests", "fixtures", "real_world")

# (context, executive_report) pairs. The golden set is hand-built to cover
# each domain skew plus the boundary cases; real_world is a captured run.
SCENARIOS = {
    "real_world": (
        os.path.join(REAL, "real_release_context.json"),
        os.path.join(REAL, "real_executive_report.json"),
    ),
}
for _name in (
    "clean_release",
    "critical_release",
    "moderate_risk_release",
    "application_heavy",
    "container_heavy",
    "infrastructure_heavy",
    "runtime_heavy",
    "mixed_domain",
):
    SCENARIOS[_name] = (
        os.path.join(GOLDEN, _name + ".json"),
        os.path.join(GOLDEN, "executive_reports", _name + ".json"),
    )


def describe(context_path, report_path):
    """One-line summary of a scenario, read from the fixtures themselves.

    Derived rather than hardcoded so this cannot drift from the fixtures the
    way a maintained description list would.
    """
    try:
        with open(context_path) as f:
            ctx = json.load(f)
        with open(report_path) as f:
            rep = json.load(f)
    except (OSError, ValueError) as exc:
        return "unreadable: {}".format(exc)

    findings = ctx.get("findings", [])
    domains = {f.get("domain") for f in findings if f.get("domain")}
    readiness = rep.get("release_readiness", {})
    verdict = readiness.get("recommendation", "?")
    health = rep.get("executive_summary", {}).get("overall_health", "?")
    return "{:>4} findings, {} domain(s), health {}, verdict {}".format(
        len(findings), len(domains), health, verdict
    )


def render(name, out_dir):
    """Render one scenario to Markdown and HTML. Returns list of paths."""
    context_path, report_path = SCENARIOS[name]
    for path in (context_path, report_path):
        if not os.path.exists(path):
            raise SystemExit("missing fixture: {}".format(path))

    os.makedirs(out_dir, exist_ok=True)
    outputs = []
    for script, ext in (("render_report.py", "md"), ("render_html_report.py", "html")):
        out = os.path.join(out_dir, "{}.{}".format(name, ext))
        # Run as subprocesses rather than importing: this is exactly how the
        # workflow invokes them, so the demo exercises the real entry points
        # including their argument parsing.
        proc = subprocess.run(
            [
                sys.executable,
                os.path.join(HERE, script),
                "--executive-report", report_path,
                "--release-context", context_path,
                "--output", out,
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            sys.stderr.write(proc.stdout + proc.stderr)
            raise SystemExit(
                "{} failed for scenario '{}'. Usually this means the fixture no "
                "longer conforms to its schema — the renderer refuses to write a "
                "non-conformant artifact.".format(script, name)
            )
        # Surface the renderer's own warnings; an unresolved citation is
        # reported this way rather than as a failure.
        for line in (proc.stdout + proc.stderr).splitlines():
            if "::warning::" in line:
                print("  ! {}: {}".format(name, line.split("::warning::")[-1].strip()))
        outputs.append(out)
    return outputs


def main():
    parser = argparse.ArgumentParser(
        description="Render release reports from committed fixtures — no cloud, no API key.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--scenario", default="real_world", choices=sorted(SCENARIOS))
    parser.add_argument("--all", action="store_true", help="render every scenario")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    parser.add_argument(
        "--out-dir",
        default=os.path.join(ROOT, "build", "demo-reports"),
        help="default: build/demo-reports/ (gitignored)",
    )
    args = parser.parse_args()

    if args.list:
        print("Available scenarios:\n")
        for name in sorted(SCENARIOS):
            print("  {:<22} {}".format(name, describe(*SCENARIOS[name])))
        print("\nRender one:  python3 scripts/demo_report.py --scenario <name>")
        return 0

    names = sorted(SCENARIOS) if args.all else [args.scenario]
    written = []
    for name in names:
        written.extend(render(name, args.out_dir))

    print("Rendered {} report(s) from fixtures — no network, no API key used.\n".format(len(written)))
    for path in written:
        print("  {}".format(os.path.relpath(path, ROOT)))
    html = [p for p in written if p.endswith(".html")]
    if html:
        print("\nOpen the HTML in a browser:\n  open {}".format(
            os.path.relpath(html[0], ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
