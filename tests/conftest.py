"""
Shared pytest fixtures for the whole suite.

Loads from tests/fixtures/golden/ (synthetic, generated through the real
pipeline functions — see build_golden_dataset.py's docstring for why) and
tests/fixtures/real_world/ (one frozen real artifact pair from an actual
CI run, validated by hand earlier this project — kept as an extra
real-data layer the synthetic fixtures can't fully substitute for).
"""
import json
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")
GOLDEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "golden")
REAL_WORLD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "real_world")

sys.path.insert(0, SCRIPTS_DIR)

SCENARIOS = [
    "clean_release",
    "moderate_risk_release",
    "critical_release",
    "infrastructure_heavy",
    "runtime_heavy",
    "application_heavy",
    "container_heavy",
    "mixed_domain",
]


@pytest.fixture(params=SCENARIOS)
def scenario(request):
    """Parametrized fixture — any test using this runs once per golden
    scenario automatically. Use this by default; only reach for a single
    named scenario when a test is specifically about that scenario's
    distinguishing trait (e.g. mixed_domain's correlations)."""
    return request.param


@pytest.fixture
def release_context(scenario):
    with open(os.path.join(GOLDEN_DIR, f"{scenario}.json")) as f:
        return json.load(f)


@pytest.fixture
def executive_report(scenario):
    with open(os.path.join(GOLDEN_DIR, "executive_reports", f"{scenario}.json")) as f:
        return json.load(f)


@pytest.fixture
def real_release_context():
    with open(os.path.join(REAL_WORLD_DIR, "real_release_context.json")) as f:
        return json.load(f)


@pytest.fixture
def real_executive_report():
    with open(os.path.join(REAL_WORLD_DIR, "real_executive_report.json")) as f:
        return json.load(f)


@pytest.fixture
def tmp_output_path(tmp_path):
    """A real temp file path for renderer outputs — tests should write
    here, never to the repo, and pytest cleans it up automatically."""
    def _path(name):
        return str(tmp_path / name)
    return _path
