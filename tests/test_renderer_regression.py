"""Renderer regression tests.

Structural checks (item count consistency) run against every scenario —
these stay valid even as renderer styling evolves. One literal snapshot
test, against the simplest scenario only (clean_release), catches
unintended output drift that structural counts alone wouldn't notice —
deliberately limited to one scenario so it doesn't become 8 brittle
snapshots that all need updating for every legitimate styling change.
"""
import os

from render_report import render_markdown
from render_html_report import render_html

SNAPSHOT_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "snapshots")


def test_markdown_risk_count_matches_input(release_context, executive_report):
    markdown = render_markdown(executive_report, release_context)
    rendered_risk_headers = markdown.count("### Risk ")
    assert rendered_risk_headers == len(executive_report["top_risks"])


def test_markdown_action_count_matches_input(release_context, executive_report):
    markdown = render_markdown(executive_report, release_context)
    rendered_action_headers = markdown.count("### Action ")
    assert rendered_action_headers == len(executive_report["priority_actions"])


def test_html_correlation_card_count_matches_input(release_context, executive_report):
    html_doc = render_html(executive_report, release_context)
    # Each correlation renders as one <article class="card ...">  inside
    # the cross-domain section specifically — count h3 titles there instead
    # of a blanket card count, since top_risks/priority_actions also use
    # .card.
    import re
    cross_domain_section = re.search(r'id="cross-domain".*?(?=<section|$)', html_doc, re.DOTALL)
    if cross_domain_section and executive_report["cross_domain_correlations"]:
        titles = re.findall(r"<h3>", cross_domain_section.group())
        assert len(titles) == len(executive_report["cross_domain_correlations"])


def test_html_assumption_row_count_matches_input(release_context, executive_report):
    html_doc = render_html(executive_report, release_context)
    assert html_doc.count('class="assumption-row"') == len(executive_report["assumptions_and_unknowns"])


def test_markdown_output_size_is_proportional_not_degenerate(release_context, executive_report):
    """A crude but real guard: output shouldn't be suspiciously tiny (a
    silently-broken render that only emits the title) or absurdly huge
    relative to input (a runaway loop/duplication bug)."""
    markdown = render_markdown(executive_report, release_context)
    input_size = len(str(executive_report))
    assert len(markdown) > 200, "rendered Markdown is suspiciously small"
    assert len(markdown) < input_size * 10, "rendered Markdown is suspiciously large relative to its input"


def test_clean_release_markdown_snapshot(release_context, executive_report, scenario):
    """The one literal snapshot — deliberately scoped to clean_release
    only. Run with UPDATE_SNAPSHOTS=1 to regenerate after an intentional
    styling change."""
    if scenario != "clean_release":
        return
    markdown = render_markdown(executive_report, release_context)
    snapshot_path = os.path.join(SNAPSHOT_DIR, "clean_release.md")
    if os.environ.get("UPDATE_SNAPSHOTS"):
        os.makedirs(SNAPSHOT_DIR, exist_ok=True)
        with open(snapshot_path, "w") as f:
            f.write(markdown)
        return
    with open(snapshot_path) as f:
        expected = f.read()
    assert markdown == expected, (
        "rendered Markdown for clean_release no longer matches the stored snapshot. "
        "If this change is intentional, regenerate with: UPDATE_SNAPSHOTS=1 pytest "
        "tests/test_renderer_regression.py -k clean_release"
    )
