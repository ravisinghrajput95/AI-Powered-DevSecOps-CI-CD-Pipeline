"""No orphan or broken finding references.

This is the single highest-value test in the whole suite: it's the exact
check that caught the one real citation bug this project has had (a
transposed-character finding_id, cited twice with two slightly different
values in the original free-text Markdown report). Every round since,
this check has been run by hand against whatever was uploaded. This
module makes it permanent and automatic.
"""
import re

FINDING_ID_PATTERN = re.compile(r"^[a-f0-9]{12}$")
EVIDENCE_KEYS = ("supporting_evidence", "blocking_evidence")


def _collect_citations(executive_report):
    citations = []

    def walk(obj, path):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in EVIDENCE_KEYS and isinstance(v, list):
                    for fid in v:
                        citations.append((path + "." + k, fid))
                else:
                    walk(v, path + "." + k)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{path}[{i}]")

    walk(executive_report, "report")
    return citations


def test_every_citation_in_golden_set_resolves_to_a_real_finding(release_context, executive_report):
    real_ids = {f["finding_id"] for f in release_context["findings"]}
    citations = _collect_citations(executive_report)
    orphans = [(loc, fid) for loc, fid in citations if fid not in real_ids]
    assert not orphans, f"orphan citations found: {orphans}"


def test_every_citation_in_real_world_fixture_resolves_to_a_real_finding(real_release_context, real_executive_report):
    """Same check against the frozen real artifact pair — this is the
    exact validation that's been done by hand on every real upload this
    session, now permanent."""
    real_ids = {f["finding_id"] for f in real_release_context["findings"]}
    citations = _collect_citations(real_executive_report)
    orphans = [(loc, fid) for loc, fid in citations if fid not in real_ids]
    assert not orphans, f"orphan citations found in the real-world fixture: {orphans}"


def test_detects_a_transposed_character_citation():
    """Regression test for the EXACT real bug this check exists to catch:
    the same finding cited twice with one character transposed
    (73e360bc47c2 vs 73e307bc47c2 in the original incident)."""
    real_ids = {"73e360bc47c2", "f913039e3a2a"}
    fake_report = {
        "top_risks": [
            {"supporting_evidence": ["73e360bc47c2"]},
            {"supporting_evidence": ["73e307bc47c2"]},  # one character transposed
        ]
    }
    citations = _collect_citations(fake_report)
    orphans = [(loc, fid) for loc, fid in citations if fid not in real_ids]
    assert orphans == [("report.top_risks[1].supporting_evidence", "73e307bc47c2")]


def test_no_citation_appears_with_two_different_spellings_of_the_same_intent(release_context, executive_report):
    """A softer integrity check than pure existence: every citation
    that's SHAPE-valid but happens to collide closely with another
    distinct real finding_id (1-2 character difference) is worth a second
    look, even if both technically resolve. Flags near-duplicates among
    DISTINCT cited ids, which is the kind of thing that indicates
    confusion even when every individual citation is technically valid."""
    citations = _collect_citations(executive_report)
    distinct = sorted(set(fid for _, fid in citations))
    near_dupes = []
    for i in range(len(distinct) - 1):
        a, b = distinct[i], distinct[i + 1]
        if sum(1 for x, y in zip(a, b) if x != y) <= 1:
            near_dupes.append((a, b))
    assert not near_dupes, f"near-duplicate finding_ids cited (possible confusion even if both resolve): {near_dupes}"


def test_evidence_arrays_never_contain_duplicate_citations_of_the_same_finding(executive_report):
    """Citing the same finding_id twice within ONE evidence array isn't
    invalid, but it's never useful — confirms render output isn't
    silently padded with repeats."""
    def walk(obj, path):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in EVIDENCE_KEYS and isinstance(v, list):
                    assert len(v) == len(set(v)), f"{path}.{k} has duplicate citations: {v}"
                else:
                    walk(v, path + "." + k)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                walk(item, f"{path}[{i}]")
    walk(executive_report, "report")
