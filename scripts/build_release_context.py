#!/usr/bin/env python3
"""
Assembles a ReleaseContext object from this pipeline's existing artifacts,
for consumption by the AI Security Analyst system prompt.

DESIGN PRINCIPLE: every piece of "reasoning work" the analyst prompt is
told NOT to do (recalculate severities, expand SBOM inventories, infer
delta status, guess scan status, count occurrences, deduplicate boilerplate
text) must be done HERE instead, deterministically, so the prompt never has
to fill a gap with a guess and never has to redo arithmetic a script already
did. Where this script can't yet do that work for real (delta analysis,
risk-acceptance records — see KNOWN LIMITATIONS below), it says so explicitly
in the output (signal_availability, delta_status: "unknown") rather than
faking a value. No inferred prioritization signal (reachability,
exploitability, business impact, internet exposure) is ever introduced here
— if no deterministic source exists for it, it stays absent and
signal_availability says so factually.

DETERMINISTIC PREPROCESSING DONE HERE (so the prompt doesn't have to):
1. Component tagging, delta_status default.
2. Recommendation deduplication: identical category-level boilerplate text
   (e.g. the same PropTypes sentence repeated once per occurrence) is hoisted
   into a single top-level `remediation_guide[category]` entry. Any
   finding-specific remainder (e.g. an exact "Fixed in: X.Y.Z" version) is
   kept on the finding as `remediation_notes`, deduplicated — no information
   lost, just redundant text removed.
3. Occurrence grouping: findings sharing (component, tool, rule_id, severity,
   category) — i.e. the same root cause — are collapsed into one entry with
   `occurrence_count` and a `locations` list, rather than N near-identical
   rows. This is the "future scale" mechanism: it activates automatically
   regardless of finding count (a unique finding just becomes a group of 1),
   so there's no separate code path or magic threshold to maintain, and it
   does today, for free, the "one fix resolves multiple findings" pattern
   the prompt would otherwise have to notice by reading repeated rows.
4. SBOM summarization (unchanged from the previous version of this script).
5. signal_availability: a factual, deterministic statement of which
   prioritization dimensions currently have ANY data source in this
   pipeline at all. This is a fact about the pipeline's current
   capabilities, not a guess about any specific finding.

KNOWN LIMITATIONS (current state of this pipeline, as of 2026-06-21):
1. No persistent storage of prior releases' findings exists yet. Without a
   baseline to diff against, every finding's `delta_status` is "unknown".
2. No risk-acceptance/exception tracking system exists yet. `risk_acceptance`
   is always an empty list unless you pass --risk-acceptance explicitly.
3. Per-tool scan_status isn't tracked upstream by merge_findings.py's output
   alone (a tool that ran-and-found-nothing looks identical to a tool that
   didn't run). Pass --scan-status to provide this explicitly; without it,
   every tool's status is "not_configured". Recognized values: "success",
   "failed", "skipped" (this release's scan didn't run, but the workflow
   exists), "not_configured" (this tool has no status-reporting mechanism
   at all, regardless of release).
4. Nothing in this pipeline produces reachability, exploitability, business
   impact, or internet-exposure signals. These are not inferred — they stay
   absent, and signal_availability records this as "not_collected".

Usage:
    build_release_context.py --output release_context.json \\
        --release-version <git-sha-or-tag> --repository <owner/repo> \\
        --backend-findings security-findings-backend.json \\
        --backend-snyk normalized-snyk-backend.json \\
        --backend-sbom normalized-sbom-backend.json \\
        --frontend-findings security-findings-frontend.json \\
        --frontend-snyk normalized-snyk-frontend.json \\
        --frontend-sbom normalized-sbom-frontend.json \\
        --supply-chain supply_chain_status.json \\
        [--risk-acceptance risk_acceptance.json] \\
        [--scan-status scan_status.json]
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from classify_finding import RECOMMENDATIONS_BY_CATEGORY

# Maps each tool's native severity vocabulary into one canonical 5-tier
# scale (critical/high/medium/low/informational), so cross-tool reasoning
# doesn't have to know that SonarCloud's "MEDIUM" and ZAP's "medium" mean
# the same thing, or that CodeQL's "note" level commonly carries real
# findings (e.g. sql-injection) despite sounding informational. Applied
# ONLY at this ReleaseContext layer — normalize_*.py's own output and the
# merged security-findings-*.json artifacts keep each tool's original
# wording untouched, since those are the audit-trail/per-tool schema, not
# the cross-tool reasoning layer.
SEVERITY_NORMALIZATION = {
    "codeql": {"error": "high", "warning": "medium", "note": "medium"},
    "sonarcloud": {"blocker": "critical", "high": "high", "medium": "medium", "low": "low", "info": "informational"},
    # GitGuardian's "severity" field is actually its validity-check result,
    # not a risk tier — "valid" (confirmed live secret) is the closest thing
    # to "critical" this data supports; "invalid" (confirmed dead) maps to
    # low; anything where validity couldn't be checked stays at medium
    # (uncertain, not confidently either way).
    "gitguardian": {"valid": "critical", "invalid": "low", "no_checker": "medium", "unknown": "medium", "failed_to_check": "medium"},
    "snyk": {"critical": "critical", "high": "high", "medium": "medium", "low": "low"},
    "zap": {"high": "high", "medium": "medium", "low": "low", "informational": "informational"},
    # kube-linter has no native per-finding severity at all (see
    # normalize_kubelinter.py's docstring) — its normalizer assigns severity
    # directly from a check-name lookup, already in this scale. Identity
    # mapping here so tag_findings' normalize_severity call doesn't flag
    # every kube-linter finding as "unrecognized" and default it to medium.
    "kube-linter": {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "informational"},
}


def normalize_severity(tool, raw_severity):
    raw = (raw_severity or "").lower()
    mapping = SEVERITY_NORMALIZATION.get(tool, {})
    if raw in mapping:
        return mapping[raw]
    print(
        f"WARNING: unrecognized severity {raw_severity!r} for tool {tool!r} — "
        f"defaulting to 'medium'. Add a mapping to SEVERITY_NORMALIZATION in "
        f"build_release_context.py.",
        file=sys.stderr,
    )
    return "medium"


def load_json(path, default):
    if not path:
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"WARNING: {path} not found — using default.", file=sys.stderr)
        return default
    except json.JSONDecodeError as e:
        print(f"WARNING: could not parse {path}: {e} — using default.", file=sys.stderr)
        return default


def tag_findings(findings, component):
    """Add component + a not-yet-available delta_status to each finding,
    rather than silently omitting the field (which would let the prompt
    assume something about freshness with no basis). Also normalizes
    severity into one cross-tool scale, preserving the tool's original
    wording as `original_severity` for traceability."""
    tagged = []
    for f in findings:
        f = dict(f)
        f["component"] = component
        f.setdefault("delta_status", "unknown")
        f["original_severity"] = f.get("severity")
        f["severity"] = normalize_severity(f.get("tool"), f.get("severity"))
        tagged.append(f)
    return tagged


def extract_remediation_note(finding, remediation_guide):
    """Split a finding's `recommendation` text into (a) the category-level
    boilerplate, hoisted once into remediation_guide, and (b) any
    finding-specific remainder (e.g. an exact fixed-in version), kept on the
    finding. Returns the remainder string, or None if there isn't one."""
    category = finding.get("category", "uncategorized")
    base_text = RECOMMENDATIONS_BY_CATEGORY.get(category)
    actual_text = finding.get("recommendation")

    if base_text is None:
        # Category not in the known table (e.g. a future category this
        # script hasn't been updated for yet) — keep the full text as-is
        # rather than guessing at a split point.
        if actual_text:
            remediation_guide.setdefault(category, actual_text)
        return None

    remediation_guide.setdefault(category, base_text)

    if not actual_text:
        return None
    if actual_text == base_text:
        return None
    if actual_text.startswith(base_text):
        remainder = actual_text[len(base_text):].strip()
        return remainder or None
    # Text doesn't match the expected category template at all (stale data,
    # or classify_finding.py's table changed since this finding was
    # generated) — keep the whole thing as a note rather than silently
    # dropping a recommendation the table no longer explains.
    return actual_text


def group_findings(findings, remediation_guide):
    """Collapse findings sharing (component, tool, rule_id, category) into
    one entry with occurrence_count + locations. This is the automatic
    grouping/summarization mechanism: it runs unconditionally, so a single
    occurrence becomes a group of one and a hundred occurrences become one
    compact entry — no finding-count threshold to tune.

    Severity is deliberately NOT part of the grouping key (changed from an
    earlier version where it was) — instead, a group's reported severity is
    the deterministic MAX across every occurrence folded into it, using
    SEVERITY_RANK's fixed ordering (critical > high > medium > low >
    informational). Never averaged, voted, or inferred. This means the
    same rule_id reported at varying severity across instances correctly
    merges into one group rather than fragmenting by severity — strictly
    more aggressive grouping, never a downgrade: a group's severity can
    only ever be raised by a new occurrence, never lowered, since it's a
    running max. original_severities (below) still captures every distinct
    raw value seen, so nothing is lost even though only the max is surfaced
    as the group's headline severity."""
    groups = {}
    order = []

    for f in findings:
        note = extract_remediation_note(f, remediation_guide)

        key = (f.get("component"), f.get("tool"), f.get("rule_id"), f.get("category"))
        if key not in groups:
            groups[key] = {
                "component": f.get("component"),
                "tool": f.get("tool"),
                "rule_id": f.get("rule_id"),
                "severity": f.get("severity"),
                "category": f.get("category"),
                "type": f.get("type"),
                "confidence": f.get("confidence"),
                "delta_status": f.get("delta_status", "unknown"),
                "occurrence_count": 0,
                "locations": [],
                "sample_message": f.get("message"),
                "remediation_notes": [],
                "original_severities": [],
            }
            # Present only for findings that carry them (currently Snyk).
            # rule_id already uniquely identifies a specific package for
            # Snyk's ID scheme, so these are consistent across every member
            # of a group — taken once from the first occurrence, not
            # collected as a list the way original_severity is.
            if f.get("package_name"):
                groups[key]["package_name"] = f["package_name"]
            if f.get("package_version"):
                groups[key]["package_version"] = f["package_version"]
            if f.get("package_manager"):
                groups[key]["package_manager"] = f["package_manager"]
            order.append(key)

        g = groups[key]
        g["occurrence_count"] += 1

        # Deterministic max aggregation — never average, vote, or infer.
        # A group's severity can only ever be raised by a new occurrence,
        # never lowered, since this is a running max over SEVERITY_RANK.
        if SEVERITY_RANK.get(f.get("severity"), -1) > SEVERITY_RANK.get(g["severity"], -1):
            g["severity"] = f.get("severity")

        file_ = f.get("file")
        line_ = f.get("line")
        loc = f"{file_}:{line_}" if file_ and line_ else (file_ or "unknown")
        if loc not in g["locations"]:
            g["locations"].append(loc)

        orig_sev = f.get("original_severity")
        if orig_sev and orig_sev not in g["original_severities"]:
            g["original_severities"].append(orig_sev)

        if note and note not in g["remediation_notes"]:
            g["remediation_notes"].append(note)

    result = []
    for key in order:
        g = groups[key]
        if not g["remediation_notes"]:
            del g["remediation_notes"]
        # Common case: every occurrence in a group shares the same original
        # severity wording — collapse to a single field rather than a
        # one-element list, for a cleaner read. Only the rare edge case
        # (the same tool/rule_id/normalized-severity/category combination
        # reported with genuinely different raw severity strings) keeps the
        # plural list, so no information is lost either way.
        original_severities = g.pop("original_severities")
        if len(original_severities) == 1:
            g["original_severity"] = original_severities[0]
        elif len(original_severities) > 1:
            g["original_severities"] = original_severities
        result.append(g)
    return result


def summarize_sbom(packages, vulnerable_package_names):
    """Collapse a raw package list into the kind of pre-summarized inventory
    the analyst prompt expects — never the full per-package list."""
    by_ecosystem = {}
    flagged = []
    for pkg in packages:
        eco = pkg.get("ecosystem", "unknown")
        by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1
        name = pkg.get("package_name")
        if name in vulnerable_package_names:
            flagged.append(f"{name}@{pkg.get('version', 'unknown')}")
    return {
        "total_packages": len(packages),
        "by_ecosystem": by_ecosystem,
        "packages_with_known_vulnerabilities": sorted(set(flagged)),
    }


def build_component_findings(component, findings_path, snyk_path):
    findings = load_json(findings_path, [])
    snyk_findings = load_json(snyk_path, [])
    return tag_findings(findings, component) + tag_findings(snyk_findings, component), snyk_findings


def build_component_sbom(sbom_path, snyk_findings):
    vulnerable_package_names = set()
    for f in snyk_findings:
        # Snyk's normalized "file" field is the dependency chain, e.g.
        # "image@tag > openssl@3.0.13-1" — the package name is also
        # embedded in rule_id/message, but the most reliable extraction
        # is from the chain's last segment before "@".
        chain = f.get("file", "")
        last_segment = chain.split(">")[-1].strip() if chain else ""
        pkg_name = last_segment.split("@")[0].strip() if "@" in last_segment else None
        if pkg_name:
            vulnerable_package_names.add(pkg_name)

    packages = load_json(sbom_path, [])
    return summarize_sbom(packages, vulnerable_package_names)


def compute_release_statistics(findings):
    """Pre-computed counts over the (already-grouped) findings list, so the
    analyst prompt never has to tally these itself. Counts grouped entries,
    not occurrence_count-weighted totals — i.e. "10 distinct findings",
    matching how a human would scan the findings list, not "36 raw hits"."""
    by_severity = {}
    by_category = {}
    by_component = {}
    for f in findings:
        # Lowercased here ONLY for this aggregate bucket — different tools
        # report severity in different cases (SonarCloud: "MEDIUM", ZAP:
        # "medium"), which are the same tier but were fragmenting into
        # separate keys in real output before this fix. Each finding's own
        # `severity` field is untouched, so per-finding traceability to the
        # tool's original wording is preserved.
        severity_key = (f["severity"] or "unknown").lower()
        by_severity[severity_key] = by_severity.get(severity_key, 0) + 1
        by_category[f["category"]] = by_category.get(f["category"], 0) + 1
        by_component[f["component"]] = by_component.get(f["component"], 0) + 1
    return {
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "by_component": by_component,
    }


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def compute_dependency_summary(findings):
    """SCA-specific summary, distinct from sbom_summary (which covers the
    built image's FULL package inventory via Syft, vulnerable or not).
    This covers only packages SCA actually flagged.

    Deliberately omits two fields from the original spec:
    - total_dependencies: needs Snyk's top-level `dependencyCount`, which
      normalize_snyk.py doesn't currently capture (it only extracts the
      vulnerabilities[] array, not the report's top-level metadata).
    - license_summary: pending a real `snyk test` run to confirm the exact
      license field shape — normalize_snyk.py's license detection is
      itself unvalidated against real output yet (see its docstring).
    Shipping a smaller, correct summary now rather than fabricating these
    two from data that isn't actually there.

    ecosystem_breakdown is omitted entirely — sbom_summary already covers
    this per-component, and the spec explicitly says not to duplicate it.
    """
    # Filtered by package_manager, NOT just tool=="snyk" — container scans
    # and SCA manifest scans both deliberately report tool:"snyk" (see
    # normalize_snyk.py's docstring on why), so tool alone can't separate
    # them. package_manager is the real, deterministic signal Snyk itself
    # reports: "deb" for this app's container scans, "pip"/"npm" for its
    # two SCA manifests. Confirmed against a real run where container-scan
    # OS packages (krb5, zlib, openssl, etc.) were incorrectly appearing
    # here before this filter existed. If more manifest ecosystems are
    # ever added (e.g. poetry, yarn), extend this allowlist.
    APPLICATION_PACKAGE_MANAGERS = ("pip", "npm")
    snyk_findings = [
        f for f in findings
        if f.get("tool") == "snyk"
        and f.get("package_name")
        and f.get("package_manager") in APPLICATION_PACKAGE_MANAGERS
    ]

    packages = {}
    for f in snyk_findings:
        pkg_key = f"{f['package_name']}@{f.get('package_version', 'unknown')}"
        entry = packages.setdefault(pkg_key, {"package": pkg_key, "severity": f["severity"], "finding_count": 0})
        if SEVERITY_RANK.get(f["severity"], 0) > SEVERITY_RANK.get(entry["severity"], 0):
            entry["severity"] = f["severity"]
        entry["finding_count"] += f.get("occurrence_count", 1)

    critical_count = sum(1 for p in packages.values() if p["severity"] == "critical")
    high_count = sum(1 for p in packages.values() if p["severity"] == "high")

    top_vulnerable = sorted(
        packages.values(),
        key=lambda p: (-SEVERITY_RANK.get(p["severity"], 0), -p["finding_count"]),
    )[:5]

    return {
        "vulnerable_dependencies": len(packages),
        "critical_dependencies": critical_count,
        "high_dependencies": high_count,
        "top_vulnerable_packages": top_vulnerable,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--backend-findings")
    parser.add_argument("--backend-snyk")
    parser.add_argument("--backend-sbom")
    parser.add_argument("--frontend-findings")
    parser.add_argument("--frontend-snyk")
    parser.add_argument("--frontend-sbom")
    parser.add_argument("--dast-findings")
    parser.add_argument("--dast-metadata")
    parser.add_argument("--supply-chain")
    parser.add_argument("--risk-acceptance")
    parser.add_argument("--scan-status")
    args = parser.parse_args()

    all_findings = []
    sbom_summary = {}

    backend_findings, backend_snyk = build_component_findings("backend", args.backend_findings, args.backend_snyk)
    all_findings.extend(backend_findings)
    sbom_summary["backend"] = build_component_sbom(args.backend_sbom, backend_snyk)

    frontend_findings, frontend_snyk = build_component_findings("frontend", args.frontend_findings, args.frontend_snyk)
    all_findings.extend(frontend_findings)
    sbom_summary["frontend"] = build_component_sbom(args.frontend_sbom, frontend_snyk)

    # DAST gets its own component value rather than "backend" or "frontend".
    # ZAP tests the live, deployed app as a whole — it doesn't (and can't)
    # assert which code component is responsible for a given finding; that
    # static-asset URLs happened to be what this particular crawl found is
    # incidental to this run, not something ZAP's data actually claims.
    # Tagging these as "frontend" would be exactly the kind of inferred
    # attribution this builder is supposed to avoid.
    dast_findings = load_json(args.dast_findings, [])
    all_findings.extend(tag_findings(dast_findings, "deployed-app"))

    # Deterministic staleness calculation — DAST isn't tied to a commit the
    # way the other tools are, so there's no "is this the right version"
    # check possible, only "how old is this data". Computing that here means
    # the analyst prompt receives a fact, not raw timestamps it would
    # otherwise have to subtract itself.
    dast_metadata_raw = load_json(args.dast_metadata, None)
    dast_scan_metadata = None
    if dast_metadata_raw:
        scanned_at_str = dast_metadata_raw.get("scanned_at")
        try:
            scanned_at = datetime.fromisoformat(scanned_at_str.replace("Z", "+00:00"))
            days_stale = (datetime.now(timezone.utc) - scanned_at).days
        except (TypeError, ValueError):
            days_stale = None
        dast_scan_metadata = {
            "run_id": dast_metadata_raw.get("run_id"),
            "scanned_at": scanned_at_str,
            "days_stale": days_stale,
        }
    elif dast_findings:
        # Findings exist but no metadata was provided (e.g. builder run
        # locally with just --dast-findings) — say so explicitly rather
        # than implying freshness by omission.
        dast_scan_metadata = {"run_id": None, "scanned_at": None, "days_stale": "unknown"}

    remediation_guide = {}
    grouped_findings = group_findings(all_findings, remediation_guide)

    supply_chain = load_json(args.supply_chain, {
        "backend": {"image_signed": "unknown", "signature_verified": "unknown"},
        "frontend": {"image_signed": "unknown", "signature_verified": "unknown"},
    })

    risk_acceptance = load_json(args.risk_acceptance, [])
    if not args.risk_acceptance:
        print(
            "NOTE: no --risk-acceptance file provided. risk_acceptance will be an "
            "empty list — this pipeline has no exception-tracking system yet.",
            file=sys.stderr,
        )

    default_scan_status = {
        component: {tool: "not_configured" for tool in ("codeql", "sonarcloud", "gitguardian", "snyk", "snyk_sca", "syft")}
        for component in ("backend", "frontend")
    }
    default_scan_status["deployed-app"] = {"zap": "not_configured"}
    scan_status = load_json(args.scan_status, default_scan_status)
    # Guaranteed present regardless of whether a passed-in --scan-status file
    # already accounts for it — release-readiness.yml's own scan-status merge
    # step doesn't know about DAST yet (it's a separate, on-demand workflow
    # not tied to a commit SHA the way the others are), so without this,
    # "deployed-app" would be silently absent rather than honestly
    # "not_configured" whenever a real --scan-status file is passed.
    scan_status.setdefault("deployed-app", {"zap": "not_configured"})
    if not args.scan_status:
        print(
            "NOTE: no --scan-status file provided. Every tool's scan_status will be "
            "'not_configured' rather than guessed — see KNOWN LIMITATIONS in this "
            "script's docstring for how to wire this up properly.",
            file=sys.stderr,
        )

    # Factual statement of pipeline capability, not a guess about any one
    # finding. "not_collected" means: no tool in this pipeline produces this
    # signal today. This is what makes "Unknown — not provided" decidable by
    # the prompt without it having to discover the gap finding-by-finding.
    signal_availability = {
        "severity": "available_per_finding",
        "confidence": "available_per_finding",
        "fix_availability": "available_per_finding_where_applicable",
        "delta_status": "not_collected",
        "reachability": "not_collected",
        "exploitability": "not_collected",
        "business_impact": "not_collected",
        "internet_exposure": "not_collected",
    }

    dependency_summary = {
        "backend": compute_dependency_summary([f for f in grouped_findings if f.get("component") == "backend"]),
        "frontend": compute_dependency_summary([f for f in grouped_findings if f.get("component") == "frontend"]),
    }

    release_context = {
        "release": {
            "version": args.release_version,
            "repository": args.repository,
            "components": ["backend", "frontend", "deployed-app"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "findings": grouped_findings,
        "remediation_guide": remediation_guide,
        "sbom_summary": sbom_summary,
        "dependency_summary": dependency_summary,
        "supply_chain": supply_chain,
        "risk_acceptance": risk_acceptance,
        "scan_status": scan_status,
        "signal_availability": signal_availability,
        "dast_scan_metadata": dast_scan_metadata,
        "release_statistics": compute_release_statistics(grouped_findings),
    }

    with open(args.output, "w") as f:
        json.dump(release_context, f, indent=2)

    raw_count = len(all_findings)
    grouped_count = len(grouped_findings)
    print(
        f"Built ReleaseContext: {raw_count} raw findings -> {grouped_count} grouped "
        f"entries -> {args.output}"
    )


if __name__ == "__main__":
    main()