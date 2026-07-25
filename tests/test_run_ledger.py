"""Guards for scripts/run_ledger.py.

The ledger's value depends entirely on one property: it must never present a
difference between runs over *different* evidence as model variance. Runs at
different commits legitimately differ — different findings, different
provenance — and reporting that spread as instability would be exactly the
overstatement this pipeline exists to prevent, committed by the tool built to
measure honesty.

That property is behavioural, not structural, so nothing else in the suite
would catch its loss. Neither would the append/dedupe logic, which fails
silently by double-counting a run and skewing every ratio computed from it.
"""
import importlib.util
import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "run_ledger.py")


def load_module():
    spec = importlib.util.spec_from_file_location("run_ledger", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ledger = load_module()


def make_report(report_id, version, correlations, recommendation="DO_NOT_APPROVE"):
    return {
        "report_id": report_id,
        "generated_at": "2026-07-25T12:00:00+00:00",
        "release_context_ref": {"repository": "r/r", "version": version},
        "executive_summary": {"overall_health": "CRITICAL", "deployment_confidence": "LOW"},
        "cross_domain_correlations": [{"title": t} for t in correlations],
        "top_risks": [{}, {}],
        "assumptions_and_unknowns": [{}],
        "release_readiness": {
            "recommendation": recommendation,
            "confidence": "HIGH",
            "blocking_evidence": ["a" * 12],
        },
    }


CONTEXT = {
    "findings": [{"finding_id": "a" * 12}],
    "scan_status": {
        "backend": {"codeql": "SUCCESS", "syft": "SUCCESS"},
        "deployed-app": {"kubearmor": "NO_SIGNAL"},
    },
}


# ── The honesty property ──────────────────────────────────────────────────

def test_summary_refuses_to_claim_variance_across_different_commits(tmp_path, capsys):
    """Two runs at two commits are not a variance measurement.

    Their findings differ, so any difference in output is partly signal. The
    summary must say so rather than presenting the spread as model noise.
    """
    path = tmp_path / "l.jsonl"
    rows = [
        ledger.build_row(make_report("a" * 16, "commit-one", ["SQL injection found"]), CONTEXT, "m"),
        ledger.build_row(make_report("b" * 16, "commit-two", ["Open firewall rule"]), CONTEXT, "m"),
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    ledger.cmd_summary(type("A", (), {"ledger": str(path)})())
    out = capsys.readouterr().out

    assert "not model noise" in out, (
        "with no repeated release version, summary must state that the spread is across "
        "different evidence — otherwise it reads as measured model instability."
    )
    assert "IDENTICAL evidence" not in out, (
        "summary claimed within-evidence stability when no commit had more than one run"
    )


def test_summary_reports_within_evidence_stability_when_it_exists(tmp_path, capsys):
    """The converse: two runs at the SAME commit are comparable, and the
    recurring-theme count is then a real measurement."""
    path = tmp_path / "l.jsonl"
    rows = [
        ledger.build_row(make_report("a" * 16, "same-commit", ["SQL injection", "Open firewall"]), CONTEXT, "m"),
        ledger.build_row(make_report("b" * 16, "same-commit", ["SQL injection", "Unsigned images"]), CONTEXT, "m"),
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    ledger.cmd_summary(type("A", (), {"ledger": str(path)})())
    out = capsys.readouterr().out

    assert "IDENTICAL evidence" in out
    assert "2 runs" in out
    # Three distinct themes across the two runs — injection (both),
    # open-network (first only), unsigned-images (second only) — so exactly
    # one of three recurs.
    assert "1/3 themes in every run" in out, out


def test_summary_flags_a_verdict_that_changed_between_runs(tmp_path, capsys):
    """A verdict flipping is the single most important thing this can detect —
    it means the deploy gate is not reproducible."""
    path = tmp_path / "l.jsonl"
    rows = [
        ledger.build_row(make_report("a" * 16, "c", ["x"], "DO_NOT_APPROVE"), CONTEXT, "m"),
        ledger.build_row(make_report("b" * 16, "c", ["x"], "APPROVE"), CONTEXT, "m"),
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    ledger.cmd_summary(type("A", (), {"ledger": str(path)})())
    out = capsys.readouterr().out
    assert "DIFFERS between runs" in out


# ── Append/dedupe ─────────────────────────────────────────────────────────

def test_recording_the_same_report_twice_does_not_double_count(tmp_path, capsys):
    """Re-running `record` on the same artifacts must be a no-op.

    A duplicated row inflates every ratio derived from the ledger while the
    file still looks well-formed.
    """
    path = tmp_path / "l.jsonl"
    er, rc = tmp_path / "er.json", tmp_path / "rc.json"
    er.write_text(json.dumps(make_report("c" * 16, "v1", ["SQL injection"])))
    rc.write_text(json.dumps(CONTEXT))
    args = type("A", (), {"executive_report": str(er), "release_context": str(rc),
                          "model": "m", "ledger": str(path)})()

    ledger.cmd_record(args)
    ledger.cmd_record(args)
    assert len(ledger.load_ledger(str(path))) == 1
    assert "already in the ledger" in capsys.readouterr().out


# ── Row construction ──────────────────────────────────────────────────────

def test_row_counts_every_scanner_across_nested_components():
    """The scan-coverage claim was once wrong by hand-counting a status block
    nested two levels deep. This is the count that replaced that arithmetic."""
    row = ledger.build_row(make_report("d" * 16, "v", ["x"]), CONTEXT, "m")
    assert row["scanners_total"] == 3          # 2 backend + 1 deployed-app
    assert row["scanners_success"] == 2        # NO_SIGNAL is not SUCCESS


def test_row_records_the_model_because_the_report_does_not():
    """ExecutiveReport v1.0 has no model field and the schema is frozen, so
    the caller supplies it. If this ever silently defaulted, runs from
    different models would be compared as if they were the same."""
    row = ledger.build_row(make_report("e" * 16, "v", ["x"]), CONTEXT, "claude-sonnet-4-6")
    assert row["model"] == "claude-sonnet-4-6"


@pytest.mark.parametrize("title,expected", [
    ("Workload Identity disabled + excessive IAM", "workload-identity+iam"),
    ("Unsigned images fail verification at deploy", "unsigned-images"),
    ("Hardcoded credentials in source", "hardcoded-secrets"),
    ("OS command injection in backend", "injection"),
    ("Open firewall rules to 0.0.0.0/0", "open-network"),
])
def test_theme_mapping_is_stable_for_known_titles(title, expected):
    """Themes are how recurrence is measured, so a mapping change silently
    rewrites history: the same correlation counted under a new name looks
    like a theme that stopped appearing."""
    assert ledger.theme_of(title) == expected


def test_unmatched_titles_fall_back_without_colliding():
    """Two unrelated unmatched titles must not collapse into one theme and
    read as a recurring finding."""
    a = ledger.theme_of("Some entirely novel correlation about widgets")
    b = ledger.theme_of("A different novel correlation about sprockets")
    assert a != b and a.startswith("other:") and b.startswith("other:")
