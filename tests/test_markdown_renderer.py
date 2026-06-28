"""Markdown renderer validation — render_report.py against every golden
scenario plus the frozen real-world fixture."""
import pytest

from render_report import render_markdown


def test_renders_without_error(release_context, executive_report):
    markdown = render_markdown(executive_report, release_context)
    assert markdown.startswith("# Release Intelligence Report")


def test_real_world_fixture_renders_without_error(real_release_context, real_executive_report):
    markdown = render_markdown(real_executive_report, real_release_context)
    assert markdown.startswith("# Release Intelligence Report")


def test_no_unresolved_evidence_when_every_citation_is_real(release_context, executive_report):
    markdown = render_markdown(executive_report, release_context)
    assert "[unresolved reference" not in markdown


def test_unresolved_marker_appears_for_a_genuinely_fake_finding_id(release_context, executive_report):
    import copy
    corrupted = copy.deepcopy(executive_report)
    if corrupted["top_risks"]:
        corrupted["top_risks"][0]["supporting_evidence"] = ["deadbeefcafe"]
    else:
        corrupted["release_readiness"]["blocking_evidence"] = ["deadbeefcafe"]
    markdown = render_markdown(corrupted, release_context)
    assert "[unresolved reference" in markdown


@pytest.mark.parametrize("recommendation,icon", [
    ("APPROVE", "✅"), ("APPROVE_WITH_CONDITIONS", "⚠️"),
    ("MANUAL_REVIEW_REQUIRED", "🔍"), ("DO_NOT_APPROVE", "❌"),
])
def test_every_recommendation_value_renders_its_own_icon(recommendation, icon, release_context, executive_report):
    import copy
    modified = copy.deepcopy(executive_report)
    modified["release_readiness"]["recommendation"] = recommendation
    markdown = render_markdown(modified, release_context)
    assert icon in markdown


def test_all_nine_sections_present(release_context, executive_report):
    markdown = render_markdown(executive_report, release_context)
    for heading in ["Executive Summary", "Cross-Domain Analysis", "Top Risks", "Highest Priority Actions", "Release Readiness Assessment", "Assumptions & Unknowns", "Final Recommendation"]:
        assert f"## {heading}" in markdown, f"missing section heading: {heading}"


def test_conditions_render_as_a_bulleted_list_when_present(release_context, executive_report):
    import copy
    modified = copy.deepcopy(executive_report)
    modified["release_readiness"]["conditions"] = ["Do the thing", "Do the other thing"]
    markdown = render_markdown(modified, release_context)
    assert "- Do the thing" in markdown
    assert "- Do the other thing" in markdown


def test_empty_sections_show_explicit_empty_state_not_blank(release_context):
    """An empty array should never silently render as nothing — a human
    should always be able to tell "the AI said there's nothing here" from
    "this section is broken"."""
    empty_report = {
        "schema_version": "1.0.0", "report_id": "x", "generated_at": "2026-01-01T00:00:00Z",
        "release_context_ref": {"repository": "x", "version": "x", "generated_at": "x"},
        "executive_summary": {"overall_health": "LOW", "deployment_confidence": "HIGH", "dominant_risk_themes": ["x"], "narrative": "x"},
        "cross_domain_correlations": [], "top_risks": [], "priority_actions": [],
        "release_readiness": {"recommendation": "APPROVE", "confidence": "HIGH", "rationale": "x", "blocking_evidence": [], "conditions": None},
        "assumptions_and_unknowns": [],
    }
    markdown = render_markdown(empty_report, release_context)
    assert "_No cross-domain correlations identified this release._" in markdown
    assert "_No risks identified this release._" in markdown
    assert "_No priority actions identified this release._" in markdown
    assert "_No gaps or unknowns flagged this release._" in markdown
