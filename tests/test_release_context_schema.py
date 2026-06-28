"""ReleaseContext schema validation — every golden scenario and the
frozen real-world fixture must conform to release_context_schema.SCHEMA."""
import jsonschema
import pytest

from release_context_schema import SCHEMA


def test_schema_itself_is_valid_json_schema():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)


def test_golden_scenario_validates(release_context):
    jsonschema.validate(release_context, SCHEMA)


def test_real_world_fixture_validates(real_release_context):
    jsonschema.validate(real_release_context, SCHEMA)


def test_every_finding_has_required_fields(release_context):
    required = ["finding_id", "component", "tool", "rule_id", "severity", "category", "type", "confidence", "occurrence_count", "domain", "sample_message"]
    for finding in release_context["findings"]:
        for field in required:
            assert field in finding, f"finding {finding.get('finding_id')} missing required field {field!r}"


def test_finding_id_is_well_formed(release_context):
    for finding in release_context["findings"]:
        fid = finding["finding_id"]
        assert len(fid) == 12, f"finding_id {fid!r} is not 12 characters"
        assert all(c in "0123456789abcdef" for c in fid), f"finding_id {fid!r} is not lowercase hex"


def test_severity_is_one_of_the_five_normalized_tiers(release_context):
    valid = {"critical", "high", "medium", "low", "informational"}
    for finding in release_context["findings"]:
        assert finding["severity"] in valid, f"finding {finding['finding_id']} has non-normalized severity {finding['severity']!r}"


def test_domain_is_one_of_the_four_values(release_context):
    valid = {"application_security", "infrastructure_security", "runtime_security", "container_security"}
    for finding in release_context["findings"]:
        assert finding["domain"] in valid, f"finding {finding['finding_id']} has invalid domain {finding['domain']!r}"


def test_scan_status_values_are_the_uppercase_enum(release_context):
    """Confirmed via a real incident this session: release_context.json
    (pre-merge) legitimately has lowercase values; final_release_context.json
    (post-merge, what this fixture represents) must always be uppercase."""
    valid = {"SUCCESS", "FAILED", "SKIPPED", "NOT_CONFIGURED"}
    for component, tools in release_context["scan_status"].items():
        for tool, status in tools.items():
            assert status in valid, f"scan_status.{component}.{tool} = {status!r} is not one of the uppercase enum values"


def test_release_statistics_total_matches_findings_count(release_context):
    assert release_context["release_statistics"]["total_findings"] == len(release_context["findings"])


def test_release_statistics_by_domain_matches_actual_findings(release_context):
    """The deterministic computation must actually match the findings —
    this is exactly the kind of thing that's safe today but could silently
    drift if compute_release_statistics ever changes without the fixture
    being regenerated."""
    import collections
    actual = collections.Counter(f["domain"] for f in release_context["findings"])
    assert dict(release_context["release_statistics"]["by_domain"]) == dict(actual)


def test_supply_chain_verification_status_is_one_of_the_four_values(release_context):
    valid = {"SUCCESS", "FAILED", "UNKNOWN", "SKIPPED"}
    for component, entry in (release_context.get("supply_chain") or {}).items():
        if "verification_status" in entry:
            assert entry["verification_status"] in valid


@pytest.mark.parametrize("scenario_name,expected_dominant_domain", [
    ("infrastructure_heavy", "infrastructure_security"),
    ("runtime_heavy", "runtime_security"),
    ("application_heavy", "application_security"),
    ("container_heavy", "container_security"),
])
def test_domain_heavy_scenarios_are_actually_dominated_by_that_domain(scenario_name, expected_dominant_domain):
    """Sanity check on the golden dataset itself, not just the schema —
    if "infrastructure_heavy" didn't actually have mostly infrastructure
    findings, every test using it to mean that would be silently wrong."""
    import json
    import os
    path = os.path.join(os.path.dirname(__file__), "fixtures", "golden", f"{scenario_name}.json")
    with open(path) as f:
        ctx = json.load(f)
    by_domain = ctx["release_statistics"]["by_domain"]
    dominant = max(by_domain, key=by_domain.get)
    assert dominant == expected_dominant_domain, f"{scenario_name} is dominated by {dominant}, not {expected_dominant_domain}"
