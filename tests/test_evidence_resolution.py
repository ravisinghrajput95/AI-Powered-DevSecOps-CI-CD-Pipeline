"""Evidence reference resolution — renderer_common.py's resolve_pointer
and build_finding_lookup in isolation, since both renderers depend on
this shared logic working correctly."""
from renderer_common import build_finding_lookup, resolve_pointer


def test_finding_lookup_contains_every_real_finding_id(release_context):
    lookup = build_finding_lookup(release_context)
    real_ids = {f["finding_id"] for f in release_context["findings"]}
    assert set(lookup.keys()) == real_ids


def test_finding_lookup_maps_to_the_correct_finding(release_context):
    lookup = build_finding_lookup(release_context)
    for f in release_context["findings"]:
        assert lookup[f["finding_id"]] is f or lookup[f["finding_id"]] == f


def test_resolve_pointer_finds_a_real_nested_value(release_context):
    assert resolve_pointer(release_context, "release.repository") == release_context["release"]["repository"]
    assert resolve_pointer(release_context, "release_statistics.total_findings") == release_context["release_statistics"]["total_findings"]


def test_resolve_pointer_walks_arbitrarily_deep(release_context):
    if release_context.get("scan_status"):
        component = next(iter(release_context["scan_status"]))
        tool = next(iter(release_context["scan_status"][component]))
        path = f"scan_status.{component}.{tool}"
        assert resolve_pointer(release_context, path) == release_context["scan_status"][component][tool]


def test_resolve_pointer_returns_none_for_a_nonexistent_path(release_context):
    assert resolve_pointer(release_context, "this.path.does.not.exist") is None


def test_resolve_pointer_returns_none_not_an_exception_for_a_path_through_a_scalar(release_context):
    """release.version is a string — trying to walk PAST it
    (release.version.nonexistent) should resolve to None, not crash."""
    assert resolve_pointer(release_context, "release.version.nonexistent") is None


def test_resolve_pointer_handles_signal_availability_paths(release_context):
    if "signal_availability" in release_context:
        for key in release_context["signal_availability"]:
            path = f"signal_availability.{key}"
            assert resolve_pointer(release_context, path) == release_context["signal_availability"][key]
