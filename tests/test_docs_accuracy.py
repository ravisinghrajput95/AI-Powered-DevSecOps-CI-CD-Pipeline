"""Guards on factual claims the documentation makes about the repository.

The test count in README.md, ARCHITECTURE.md and CLAUDE.md went stale four
times in a single day (507 -> 524 -> 529 -> 533), each time because adding
tests is exactly the change least likely to prompt someone to reread the
prose. A number a reader can check and find wrong undermines the numbers they
cannot check, which for a repository whose entire pitch is "the pipeline does
not overstate what it found" is a worse cost than it first appears.

These assert only claims with one verifiable answer. Nothing here polices
wording.
"""
import glob
import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DOCS_CLAIMING_TEST_COUNT = ["README.md", "ARCHITECTURE.md", "CLAUDE.md"]


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


def test_policy_counts_in_claude_md_match_the_policy_directories():
    """CLAUDE.md states exact policy counts; they are trivially checkable."""
    text = open(os.path.join(ROOT, "CLAUDE.md"), encoding="utf-8").read()

    kyverno_claimed = re.search(r"kyverno/ \((\d+) ClusterPolicies\)", text)
    kubearmor_claimed = re.search(r"kubearmor/ \((\d+) policies\)", text)
    assert kyverno_claimed and kubearmor_claimed, "policy-count claims not found in CLAUDE.md"

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


def test_workflow_count_in_claude_md_matches_reality():
    text = open(os.path.join(ROOT, "CLAUDE.md"), encoding="utf-8").read()
    claimed = re.search(r"(\d+) CI/CD \+ security workflows", text)
    assert claimed, "workflow-count claim not found in CLAUDE.md"
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
