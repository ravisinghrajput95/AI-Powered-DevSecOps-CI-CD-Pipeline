"""Guards on factual claims the documentation makes about the repository.

The test count in README.md and ARCHITECTURE.md went stale four
times in a single day (507 -> 524 -> 529 -> 533), each time because adding
tests is exactly the change least likely to prompt someone to reread the
prose. A number a reader can check and find wrong undermines the numbers they
cannot check, which for a repository whose entire pitch is "the pipeline does
not overstate what it found" is a worse cost than it first appears.

These assert only claims with one verifiable answer. Nothing here polices
wording.
"""
import glob
import json
import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DOCS_CLAIMING_TEST_COUNT = ["README.md", "ARCHITECTURE.md"]


def collected_test_count():
    """Ask pytest itself rather than hardcoding a second copy of the number."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", os.path.join(ROOT, "tests"), "--collect-only", "-q"],
        capture_output=True, text=True, cwd=ROOT,
    )
    match = re.search(r"(\d+) tests? collected", proc.stdout)
    if not match:
        pytest.skip("could not determine collected test count from pytest output")
    return int(match.group(1))


def claimed_counts(filename):
    """Every 'N automated tests' / 'N-test suite' style claim in a document."""
    text = open(os.path.join(ROOT, filename), encoding="utf-8").read()
    return [
        int(n)
        for n in re.findall(r"(\d{3,4})[\s-]+(?:automated )?tests?\b", text)
        + re.findall(r"(\d{3,4})-test suite", text)
        # README carries a shields.io badge, e.g. `tests-559%20passing`. It is
        # the most visible count in the repository and the least likely to be
        # remembered, since it lives in a URL rather than prose.
        + re.findall(r"tests?-(\d{3,4})%20passing", text)
    ]


@pytest.mark.parametrize("doc", DOCS_CLAIMING_TEST_COUNT)
def test_documented_test_count_matches_reality(doc):
    actual = collected_test_count()
    for claimed in claimed_counts(doc):
        assert claimed == actual, (
            "{} claims {} tests; pytest collects {}. Update the prose — a number a "
            "reader can check and find wrong discredits the ones they cannot."
            .format(doc, claimed, actual)
        )


def test_policy_counts_in_readme_match_the_policy_directories():
    """README's project-structure block states exact policy counts; they are
    trivially checkable, and were guarded here before CLAUDE.md was removed."""
    text = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()

    kyverno_claimed = re.search(r"(\d+) Kyverno ClusterPolicies", text)
    kubearmor_claimed = re.search(r"(\d+) KubeArmor runtime policies", text)
    assert kyverno_claimed and kubearmor_claimed, "policy-count claims not found in README.md"

    kyverno_actual = sum(
        1 for p in glob.glob(os.path.join(ROOT, "policies", "kyverno", "*.yaml"))
        if "kind: ClusterPolicy" in open(p, encoding="utf-8").read()
    )
    kubearmor_actual = sum(
        open(p, encoding="utf-8").read().count("kind: KubeArmorPolicy")
        for p in glob.glob(os.path.join(ROOT, "policies", "kubearmor", "**", "*.y*ml"), recursive=True)
    )
    assert int(kyverno_claimed.group(1)) == kyverno_actual
    assert int(kubearmor_claimed.group(1)) == kubearmor_actual


def test_workflow_count_in_readme_matches_reality():
    text = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    claimed = re.search(r"(\d+) CI/CD \+ security workflows", text)
    assert claimed, "workflow-count claim not found in README.md"
    actual = len(glob.glob(os.path.join(ROOT, ".github", "workflows", "*.y*ml")))
    assert int(claimed.group(1)) == actual


def test_committed_sample_report_leaks_no_live_infrastructure():
    """A live LoadBalancer IP was published here in 34 places, pointing at an
    internet-facing instance of a deliberately vulnerable app — the exact
    thing README.md's opening warning tells people never to create.

    Project ids and cluster addresses must appear as placeholders.
    """
    offenders = []
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    allowed = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8"}
    for path in glob.glob(os.path.join(ROOT, "reports", "**", "*.*"), recursive=True):
        if not path.endswith((".md", ".html", ".json")):
            continue
        text = open(path, encoding="utf-8", errors="replace").read()
        for found in set(ip_pattern.findall(text)) - allowed:
            # CVE identifiers and version strings can look like dotted quads;
            # only flag values used as a scan target or host.
            if re.search(r"https?://" + re.escape(found), text):
                offenders.append("{}: {}".format(os.path.relpath(path, ROOT), found))
    assert not offenders, (
        "live host addresses in committed reports:\n  " + "\n  ".join(sorted(offenders))
    )


def test_scan_coverage_claim_matches_the_run_ledger():
    """reports/README.md states how many scanners reported SUCCESS.

    That number was wrong when first written — claimed 17, actually 19 —
    because it was counted by hand from a status block nested two levels deep.
    reports/run_ledger.jsonl records the real counts per run, so the claim is
    now checkable against the recorded row for the committed report rather
    than against someone's arithmetic.
    """
    readme = os.path.join(ROOT, "reports", "README.md")
    text = open(readme, encoding="utf-8").read()

    claim = re.search(r"\*\*(\d+) of (\d+) scanners", text)
    assert claim, "reports/README.md no longer states a scan-coverage claim"
    claimed_success, claimed_total = int(claim.group(1)), int(claim.group(2))

    report_id = re.search(r"\*\*Report ID\*\* \| `([0-9a-f]+)`", text)
    assert report_id, "reports/README.md no longer states a Report ID"

    ledger = os.path.join(ROOT, "reports", "run_ledger.jsonl")
    if not os.path.exists(ledger):
        pytest.skip("run ledger not present")
    rows = [json.loads(line) for line in open(ledger, encoding="utf-8") if line.strip()]
    match = [r for r in rows if r.get("report_id") == report_id.group(1)]
    assert match, (
        "the report committed in reports/sample/ ({}) has no row in the run ledger — "
        "record it with scripts/run_ledger.py".format(report_id.group(1))
    )
    row = match[0]
    assert (claimed_success, claimed_total) == (row["scanners_success"], row["scanners_total"]), (
        "reports/README.md claims {}/{} scanners SUCCESS; the ledger records {}/{} for "
        "report {}.".format(claimed_success, claimed_total,
                            row["scanners_success"], row["scanners_total"], row["report_id"])
    )
