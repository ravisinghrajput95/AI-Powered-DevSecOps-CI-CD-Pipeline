"""ExecutiveReport schema validation."""
import jsonschema
import pytest

from executive_report_schema import SCHEMA


def test_schema_itself_is_valid_json_schema():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)


def test_golden_scenario_validates(executive_report):
    jsonschema.validate(executive_report, SCHEMA)


def test_real_world_fixture_validates(real_executive_report):
    jsonschema.validate(real_executive_report, SCHEMA)


def test_recommendation_is_one_of_four_values(executive_report):
    valid = {"APPROVE", "APPROVE_WITH_CONDITIONS", "MANUAL_REVIEW_REQUIRED", "DO_NOT_APPROVE"}
    assert executive_report["release_readiness"]["recommendation"] in valid


def test_all_four_recommendation_values_appear_somewhere_in_the_golden_set():
    """Not a per-scenario test — a test that the GOLDEN SET AS A WHOLE
    actually exercises every enum value. If someone edits a golden
    scenario and accidentally collapses everything to DO_NOT_APPROVE
    again, this is what catches that."""
    import glob
    import json
    import os
    seen = set()
    golden_dir = os.path.join(os.path.dirname(__file__), "fixtures", "golden", "executive_reports")
    for path in glob.glob(os.path.join(golden_dir, "*.json")):
        with open(path) as f:
            seen.add(json.load(f)["release_readiness"]["recommendation"])
    expected = {"APPROVE", "APPROVE_WITH_CONDITIONS", "MANUAL_REVIEW_REQUIRED", "DO_NOT_APPROVE"}
    assert seen == expected, f"golden set only covers {seen}, missing {expected - seen}"


def test_evidence_arrays_contain_only_well_formed_finding_ids(executive_report):
    import re
    pattern = re.compile(r"^[a-f0-9]{12}$")
    for key in ("supporting_evidence", "blocking_evidence"):
        def walk(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == key and isinstance(v, list):
                        for fid in v:
                            assert pattern.match(fid), f"{key} contains malformed finding_id {fid!r}"
                    else:
                        walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)
        walk(executive_report)


def test_conditions_is_array_or_null_never_missing(executive_report):
    assert "conditions" in executive_report["release_readiness"]
    assert executive_report["release_readiness"]["conditions"] is None or isinstance(executive_report["release_readiness"]["conditions"], list)


def test_dominant_risk_themes_are_short_labels_not_sentences(executive_report):
    """Confirmed via a real run this session: with no guidance, the model
    produced 80-110 char full sentences here, which breaks the pill/tag
    rendering this field is designed for. Schema allows up to 130 as a
    safety margin, but the golden set itself should model the actually-
    intended style, not just squeak under the limit."""
    for theme in executive_report["executive_summary"]["dominant_risk_themes"]:
        assert len(theme) <= 90, f"theme {theme!r} ({len(theme)} chars) reads more like a sentence than a label"


def test_assumptions_related_to_is_a_pointer_not_a_restated_value(executive_report):
    """related_to should look like a dotted path into ReleaseContext
    (e.g. "scan_status.backend.codeql"), not prose."""
    for a in executive_report["assumptions_and_unknowns"]:
        related_to = a["related_to"]
        assert " " not in related_to, f"related_to {related_to!r} looks like prose, not a pointer"
        assert "." in related_to, f"related_to {related_to!r} doesn't look like a dotted path"
