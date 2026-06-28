"""Contract backward/forward compatibility.

Two genuinely different things get tested here, and they should have
opposite outcomes:
- A NEW, unknown FIELD appearing (forward compatibility) should be
  accepted gracefully — additionalProperties:true exists specifically
  for this.
- A core enum value going outside its FROZEN set (domain, severity,
  scan_status, recommendation) should be REJECTED — these are closed
  enums by deliberate architectural decision, not extension points. A
  5th domain value appearing would mean assign_domain() malfunctioned,
  and the schema correctly catching that is the system working, not
  failing.
"""
import copy

import jsonschema
import pytest

from release_context_schema import SCHEMA as RELEASE_CONTEXT_SCHEMA
from executive_report_schema import SCHEMA as EXECUTIVE_REPORT_SCHEMA


def test_unknown_additional_field_on_a_finding_does_not_break_validation(release_context):
    """A future tool-specific field (the same way package_manager/
    package_name already vary by tool) shouldn't require a schema change
    to be accepted."""
    modified = copy.deepcopy(release_context)
    if modified["findings"]:
        modified["findings"][0]["some_future_field_nobody_has_invented_yet"] = "some value"
        jsonschema.validate(modified, RELEASE_CONTEXT_SCHEMA)


def test_unknown_additional_top_level_key_does_not_break_validation(release_context):
    """A future top-level section (e.g. the documented-but-not-yet-built
    risk_acceptance field) shouldn't require a schema change to coexist."""
    modified = copy.deepcopy(release_context)
    modified["some_future_top_level_section"] = {"anything": "goes here"}
    jsonschema.validate(modified, RELEASE_CONTEXT_SCHEMA)


def test_a_fifth_domain_value_is_correctly_rejected_not_silently_accepted(release_context):
    """domain is a closed, frozen 4-value enum by deliberate architectural
    decision — NOT an extension point. If this ever passes, it means the
    schema silently started accepting whatever assign_domain() produces,
    even if it malfunctioned."""
    modified = copy.deepcopy(release_context)
    if modified["findings"]:
        modified["findings"][0]["domain"] = "some_new_domain_nobody_agreed_to"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(modified, RELEASE_CONTEXT_SCHEMA)


def test_a_fifth_recommendation_value_is_correctly_rejected(release_context, executive_report):
    """Same principle for ExecutiveReport's recommendation enum."""
    modified = copy.deepcopy(executive_report)
    modified["release_readiness"]["recommendation"] = "MAYBE_APPROVE_IDK"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(modified, EXECUTIVE_REPORT_SCHEMA)


def test_an_unnormalized_scan_status_value_is_correctly_rejected(release_context):
    """final_release_context.json (post-merge) must always use the
    uppercase enum — a lowercase value slipping through (e.g. if
    normalize_scan_status() were ever bypassed) should fail validation,
    not pass silently."""
    modified = copy.deepcopy(release_context)
    if modified.get("scan_status"):
        component = next(iter(modified["scan_status"]))
        tool = next(iter(modified["scan_status"][component]))
        modified["scan_status"][component][tool] = "success"  # lowercase — wrong for this contract
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(modified, RELEASE_CONTEXT_SCHEMA)


def test_missing_signal_availability_is_correctly_rejected():
    """Regression test for a real incident: compose_release_context.py
    used to silently drop signal_availability entirely. A
    final_release_context.json missing it should fail validation, not
    pass with a confusing downstream KeyError later."""
    minimal = {
        "schema_version": "1.0.0",
        "release": {"version": "x", "repository": "x", "components": [], "generated_at": "x"},
        "provenance": {},
        "findings": [],
        "remediation_guide": {},
        "scan_status": {},
        "release_statistics": {"total_findings": 0, "by_severity": {}, "by_category": {}, "by_component": {}, "by_domain": {}},
        # signal_availability deliberately omitted
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(minimal, RELEASE_CONTEXT_SCHEMA)


def test_renderers_handle_a_minimal_schema_valid_report_without_crashing(release_context):
    """A report with every array empty and every optional field null is
    schema-valid and should render cleanly with explicit empty states —
    not crash, not render blank with no explanation."""
    from render_report import render_markdown
    from render_html_report import render_html

    minimal_report = {
        "schema_version": "1.0.0", "report_id": "x", "generated_at": "2026-01-01T00:00:00Z",
        "release_context_ref": {"repository": "x", "version": "x", "generated_at": "x"},
        "executive_summary": {"overall_health": "LOW", "deployment_confidence": "HIGH", "dominant_risk_themes": ["Nothing notable"], "narrative": "Nothing notable this release."},
        "cross_domain_correlations": [], "top_risks": [], "priority_actions": [],
        "release_readiness": {"recommendation": "APPROVE", "confidence": "HIGH", "rationale": "Clean release.", "blocking_evidence": [], "conditions": None},
        "assumptions_and_unknowns": [],
    }
    jsonschema.validate(minimal_report, EXECUTIVE_REPORT_SCHEMA)
    markdown = render_markdown(minimal_report, release_context)
    html_doc = render_html(minimal_report, release_context)
    assert markdown and html_doc
