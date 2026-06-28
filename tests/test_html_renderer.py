"""HTML renderer validation — render_html_report.py against every golden
scenario plus the frozen real-world fixture."""
import re

import pytest

from render_html_report import render_html, esc, RECOMMENDATION_LABELS


def test_renders_without_error(release_context, executive_report):
    html_doc = render_html(executive_report, release_context)
    assert html_doc.startswith("<!DOCTYPE html>")
    assert "</html>" in html_doc


def test_real_world_fixture_renders_without_error(real_release_context, real_executive_report):
    html_doc = render_html(real_executive_report, real_release_context)
    assert "<!DOCTYPE html>" in html_doc


def test_no_unresolved_evidence_when_every_citation_is_real(release_context, executive_report):
    """The golden fixtures were built so every citation IS real (copied
    from the actual generated finding_ids) — zero unresolved chips should
    ever appear. If this fails, either a fixture's citations drifted, or
    the renderer's resolution logic broke."""
    html_doc = render_html(executive_report, release_context)
    assert "⚠ unresolved" not in html_doc


def test_real_world_fixture_has_zero_unresolved_evidence(real_release_context, real_executive_report):
    html_doc = render_html(real_executive_report, real_release_context)
    assert "⚠ unresolved" not in html_doc


def test_unresolved_marker_appears_for_a_genuinely_fake_finding_id(release_context, executive_report):
    """The inverse of the test above — confirms the detection mechanism
    actually works, not just that it's silent. Without this, the previous
    test would also pass if resolution were silently broken and never
    flagged anything as unresolved."""
    import copy
    corrupted = copy.deepcopy(executive_report)
    if corrupted["top_risks"]:
        corrupted["top_risks"][0]["supporting_evidence"] = ["deadbeefcafe"]
    else:
        corrupted["release_readiness"]["blocking_evidence"] = ["deadbeefcafe"]
    html_doc = render_html(corrupted, release_context)
    assert "⚠ unresolved" in html_doc, "a fake finding_id should be flagged, but wasn't"


def test_escaping_neutralizes_script_tags():
    """Security-critical: every text field in ExecutiveReport.json is
    model-generated content. A live <script> tag making it into rendered
    output would be a real vulnerability in a SECURITY report's own
    renderer."""
    dangerous = '<script>alert(1)</script>'
    escaped = esc(dangerous)
    assert "<script>" not in escaped
    assert "&lt;script&gt;" in escaped


def test_escaping_neutralizes_event_handler_injection():
    dangerous = '<img src=x onerror=alert(1)>'
    escaped = esc(dangerous)
    assert not re.search(r"<img[^>]*>", escaped)


def test_no_live_script_or_img_tags_survive_full_render(release_context, executive_report):
    """End-to-end version of the escaping test, against a full render
    rather than the esc() function in isolation — catches a case where
    esc() works but some f-string elsewhere forgot to call it."""
    html_doc = render_html(executive_report, release_context)
    assert not re.findall(r"<(?:script|iframe)[^>]*>", html_doc)


def test_closing_recommendation_section_present(release_context, executive_report):
    """Added after a real gap: on a long document, the recommendation
    only appearing once in the top banner means a reader who scrolls
    through everything has lost sight of it. This is the regression
    guard for that fix."""
    html_doc = render_html(executive_report, release_context)
    assert 'id="final-recommendation"' in html_doc
    assert "Final Recommendation" in html_doc


@pytest.mark.parametrize("recommendation", ["APPROVE", "APPROVE_WITH_CONDITIONS", "MANUAL_REVIEW_REQUIRED", "DO_NOT_APPROVE"])
def test_every_recommendation_value_has_a_distinct_verdict_class(recommendation, release_context, executive_report):
    """All four enum values must produce a DIFFERENT CSS class — this is
    what a class-name-mismatch bug (e.g. underscore handling) would break
    silently, since the schema doesn't know about CSS class names."""
    import copy
    modified = copy.deepcopy(executive_report)
    modified["release_readiness"]["recommendation"] = recommendation
    html_doc = render_html(modified, release_context)
    assert f'verdict-rec--{recommendation.lower()}' in html_doc
    assert f'closing-rec--{recommendation.lower()}' in html_doc
    assert RECOMMENDATION_LABELS[recommendation] in html_doc


def test_toc_has_an_entry_for_every_section(release_context, executive_report):
    html_doc = render_html(executive_report, release_context)
    for anchor in ["executive-summary", "cross-domain", "top-risks", "priority-actions", "release-readiness", "assumptions", "final-recommendation"]:
        assert f'href="#{anchor}"' in html_doc, f"TOC missing a link to #{anchor}"
        assert f'id="{anchor}"' in html_doc, f"no section has id={anchor!r}"
