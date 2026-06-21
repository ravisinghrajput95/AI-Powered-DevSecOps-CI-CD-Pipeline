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
   every tool's status is "unknown".
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
    assume something about freshness with no basis)."""
    tagged = []
    for f in findings:
        f = dict(f)
        f["component"] = component
        f.setdefault("delta_status", "unknown")
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
    """Collapse findings sharing (component, tool, rule_id, severity,
    category) into one entry with occurrence_count + locations. This is the
    automatic grouping/summarization mechanism: it runs unconditionally, so
    a single occurrence becomes a group of one and a hundred occurrences
    become one compact entry — no finding-count threshold to tune."""
    groups = {}
    order = []

    for f in findings:
        note = extract_remediation_note(f, remediation_guide)

        key = (f.get("component"), f.get("tool"), f.get("rule_id"), f.get("severity"), f.get("category"))
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
            }
            order.append(key)

        g = groups[key]
        g["occurrence_count"] += 1

        file_ = f.get("file")
        line_ = f.get("line")
        loc = f"{file_}:{line_}" if file_ and line_ else (file_ or "unknown")
        if loc not in g["locations"]:
            g["locations"].append(loc)

        if note and note not in g["remediation_notes"]:
            g["remediation_notes"].append(note)

    result = []
    for key in order:
        g = groups[key]
        if not g["remediation_notes"]:
            del g["remediation_notes"]
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
        component: {tool: "unknown" for tool in ("codeql", "sonarcloud", "gitguardian", "snyk", "syft")}
        for component in ("backend", "frontend")
    }
    default_scan_status["deployed-app"] = {"zap": "unknown"}
    scan_status = load_json(args.scan_status, default_scan_status)
    # Guaranteed present regardless of whether a passed-in --scan-status file
    # already accounts for it — release-readiness.yml's own scan-status merge
    # step doesn't know about DAST yet (it's a separate, on-demand workflow
    # not tied to a commit SHA the way the others are), so without this,
    # "deployed-app" would be silently absent rather than honestly "unknown"
    # whenever a real --scan-status file is passed.
    scan_status.setdefault("deployed-app", {"zap": "unknown"})
    if not args.scan_status:
        print(
            "NOTE: no --scan-status file provided. Every tool's scan_status will be "
            "'unknown' rather than guessed — see KNOWN LIMITATIONS in this script's "
            "docstring for how to wire this up properly.",
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
        "supply_chain": supply_chain,
        "risk_acceptance": risk_acceptance,
        "scan_status": scan_status,
        "signal_availability": signal_availability,
        "dast_scan_metadata": dast_scan_metadata,
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