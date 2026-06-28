"""Cross-domain reasoning integrity.

What this CAN'T test: whether a correlation is a GOOD insight — that's a
judgment call, not a deterministic property. What it CAN test: whether
the correlation's structural claims are internally consistent with the
evidence it cites. If a correlation says affected_domains=[infra,
runtime] but every cited finding_id actually has domain=infra, that's a
real, checkable inconsistency regardless of whether the underlying
insight is good.
"""
from renderer_common import build_finding_lookup


def test_correlation_affected_domains_overlaps_the_actual_domains_of_its_evidence(release_context, executive_report):
    """Every domain claimed in affected_domains should be backed by at
    least one cited finding actually in that domain — "supply_chain" is
    the one allowed exception (see Schema Reference in system_prompt.md:
    it's a legitimate cross-cutting concern with no finding-level domain
    of its own)."""
    lookup = build_finding_lookup(release_context)
    for corr in executive_report["cross_domain_correlations"]:
        evidence_domains = {lookup[fid]["domain"] for fid in corr["supporting_evidence"] if fid in lookup}
        claimed_domains = set(corr["affected_domains"]) - {"supply_chain"}
        unbacked = claimed_domains - evidence_domains
        assert not unbacked, (
            f"correlation {corr['correlation_id']!r} claims domains {unbacked} "
            f"with no cited evidence actually in that domain (evidence is in {evidence_domains})"
        )


def test_mixed_domain_scenario_has_a_genuinely_cross_domain_correlation():
    """Sanity check on the golden fixture's own design intent — corr-1 in
    mixed_domain was deliberately built to span infrastructure_security
    AND runtime_security. If this ever stops being true, the fixture no
    longer tests what it claims to."""
    import json
    import os
    path = os.path.join(os.path.dirname(__file__), "fixtures", "golden", "executive_reports", "mixed_domain.json")
    with open(path) as f:
        report = json.load(f)
    corr1 = next(c for c in report["cross_domain_correlations"] if c["correlation_id"] == "corr-1")
    assert len(set(corr1["affected_domains"])) >= 2, "corr-1 should genuinely span multiple domains"


def test_mixed_domain_scenario_has_a_single_domain_multi_finding_correlation():
    """The OTHER deliberate pattern in mixed_domain — corr-2, the
    cryptography CVE pair, is single-domain but multi-finding. This is
    the case minItems:1 (relaxed from 2) was specifically about — a
    real, valuable correlation that's compounding WITHIN one domain, not
    across domains."""
    import json
    import os
    path = os.path.join(os.path.dirname(__file__), "fixtures", "golden", "executive_reports", "mixed_domain.json")
    with open(path) as f:
        report = json.load(f)
    corr2 = next(c for c in report["cross_domain_correlations"] if c["correlation_id"] == "corr-2")
    assert len(set(corr2["affected_domains"])) == 1
    assert len(corr2["supporting_evidence"]) >= 2


def test_correlation_supporting_evidence_is_never_empty(executive_report):
    """A correlation citing zero evidence is pure speculation — this is
    exactly the constraint that caught a real model slip this session
    (cross_domain_correlations[4].supporting_evidence was [], correctly
    rejected and corrected on retry)."""
    for corr in executive_report["cross_domain_correlations"]:
        assert len(corr["supporting_evidence"]) >= 1, f"correlation {corr['correlation_id']!r} cites zero evidence"


def test_top_risk_ranking_is_array_order_not_a_separate_field(executive_report):
    """Confirmed design decision: array order IS priority, no separate
    rank integer that could drift from the actual order."""
    for risk in executive_report["top_risks"]:
        assert "priority" not in risk and "rank" not in risk, "top_risks should not have a separate rank field — order is the rank"


def test_blocking_evidence_for_do_not_approve_cites_at_least_one_critical_or_high_finding(release_context, executive_report):
    """A DO_NOT_APPROVE recommendation should be backed by evidence that
    actually justifies it — not a structural guarantee the schema can
    enforce on its own, but a sanity check worth having."""
    rr = executive_report["release_readiness"]
    if rr["recommendation"] != "DO_NOT_APPROVE":
        return
    lookup = build_finding_lookup(release_context)
    severities = {lookup[fid]["severity"] for fid in rr["blocking_evidence"] if fid in lookup}
    assert severities & {"critical", "high"}, f"DO_NOT_APPROVE blocking_evidence has no critical/high finding: severities seen = {severities}"
