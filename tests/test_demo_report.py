"""Guards for scripts/demo_report.py — the no-cloud entry point.

This is the one path a stranger evaluating the repo will actually run, and it
is the easiest thing in the tree to break silently: it references nine fixture
pairs by filename, so renaming or moving any fixture breaks the demo while
every other test keeps passing. Nothing else in the suite reads those paths.
"""
import importlib.util
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "scripts", "demo_report.py")


def load_demo():
    spec = importlib.util.spec_from_file_location("demo_report", DEMO)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


demo = load_demo()


def test_every_scenario_fixture_exists():
    """A renamed fixture must fail here, not when someone tries the demo."""
    missing = []
    for name, (context, report) in sorted(demo.SCENARIOS.items()):
        for path in (context, report):
            if not os.path.exists(path):
                missing.append("{}: {}".format(name, os.path.relpath(path, ROOT)))
    assert not missing, "demo_report.py references missing fixtures:\n  " + "\n  ".join(missing)


def test_scenarios_cover_the_full_verdict_range():
    """The demo must not present the pipeline as a machine that only says no.

    CloudCart is deliberately vulnerable, so the real report is always
    DO_NOT_APPROVE. If the golden scenarios covering APPROVE and the
    intermediate verdicts were dropped, the demo would imply the engine has
    exactly one output.
    """
    verdicts = set()
    for context, report in demo.SCENARIOS.values():
        verdicts.add(demo.describe(context, report).rsplit("verdict ", 1)[-1])
    assert "APPROVE" in verdicts, "no scenario demonstrates an approval; verdicts seen: {}".format(
        sorted(verdicts)
    )
    assert len(verdicts) >= 3, "expected a spread of verdicts, got {}".format(sorted(verdicts))


def test_describe_reads_real_values_from_fixtures():
    """describe() derives its summary from the fixtures rather than a
    hardcoded table, so a schema field rename must surface as '?' here."""
    line = demo.describe(*demo.SCENARIOS["real_world"])
    assert "?" not in line, "describe() fell back to a placeholder: {!r}".format(line)
    assert "findings" in line and "verdict" in line


@pytest.mark.parametrize("scenario", ["clean_release", "real_world"])
def test_demo_renders_without_network_or_credentials(scenario, tmp_path):
    """End-to-end, with ANTHROPIC_API_KEY scrubbed from the environment.

    The claim in the README is that this needs no key. Removing it from the
    child environment is what makes that a test rather than an assertion.
    """
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    proc = subprocess.run(
        [sys.executable, DEMO, "--scenario", scenario, "--out-dir", str(tmp_path)],
        capture_output=True, text=True, env=env, cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for ext in ("md", "html"):
        out = tmp_path / "{}.{}".format(scenario, ext)
        assert out.exists(), "{} not written".format(out)
        assert out.stat().st_size > 1000, "{} suspiciously small".format(out)
