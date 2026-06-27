#!/usr/bin/env python3
"""
Composes the single, canonical final_release_context.json from the two
existing builder outputs:
    release_context.json  (build_release_context.py  — backend, frontend, deployed-app)
    infra_context.json    (build_infra_context.py     — infrastructure, terraform)

This is the ONE merge point in the v1.0 frozen architecture. Per the
agreed design:
- Every downstream consumer (AI agent, Markdown, Slack, PR comment,
  dashboard) reads ONLY final_release_context.json — never the two
  intermediates directly. Enforce this structurally in whatever workflow
  calls this script: give downstream jobs only the final artifact as
  input, not the intermediates. (Keep uploading the intermediates as CI
  artifacts anyway — every real bug found integrating Checkov/Kyverno/
  KubeArmor this project's history was caught by inspecting an
  intermediate, not the final merged object.)
- findings[] stays FLAT. No application_security.findings/
  infrastructure_security.findings nesting. domain is a tag on each
  finding, not a partition of the array.
- This script, not the builders, owns: merging findings, assigning
  domain, recomputing release_statistics, merging remediation_guides,
  validating release metadata, and stable-sorting findings. The builders'
  own partial release_statistics/by_domain are NOT trusted or reused here
  — recomputed fresh on the full merged set.

MERGE VALIDATION — repository vs. version, deliberately different rules:
- repository MUST match between the two inputs. A mismatch means the
  wrong artifact got passed in (wrong repo entirely), which is a real
  error, not a staleness fact — HARD FAILS.
- version (commit SHA) MISMATCHING IS THE NORMAL CASE, not an error.
  Confirmed via this project's actual trigger configuration:
  infra-security-scan.yaml only fires on helm/**, terraform/** path
  changes; the app-sec chain fires on backend/**, frontend/** changes.
  These are disjoint for the overwhelming majority of real commits, so
  release_context.json and infra_context.json will almost always be
  built from different commits. Hard-failing on that would mean this
  script almost never succeeds. Instead: surfaced as provenance/
  staleness data (see provenance section below), same pattern already
  proven out in this project for DAST/Kyverno/KubeArmor's
  *_scan_metadata (days_stale) fields — never silently assumed fresh,
  never blocking.

DOMAIN ASSIGNMENT happens here (assign_domain(), imported from
build_release_context.py), on the merged set, once — not duplicated per
normalizer or per builder.

FINDING MERGE: simple concatenation, not a re-run of group_findings'
deduplication. Verified safe: group_findings' key is (component, tool,
rule_id, category), and the two input files use entirely disjoint
component vocabularies (backend/frontend/deployed-app vs.
infrastructure/terraform) — no possible key collision between the two
sources, so concatenation is correct, not just convenient.

REMEDIATION GUIDE MERGE: plain dict union ({**a, **b}). Verified safe:
both builders' remediation_guide entries are produced by the SAME shared
classify_recommendation() in classify_finding.py — any category key
present in both guides is guaranteed to carry identical text, so there's
no real conflict to resolve, just a union.

PROVENANCE: tracked per logical source, NOT collapsed into one shared
"runtime_security: {generated_at, days_stale}" — that would lose real
information, since ZAP/Kyverno/KubeArmor are three independently-
schedulable jobs (confirmed: dast_scan_metadata/kyverno_scan_metadata/
kubearmor_scan_metadata already exist as three separate fields in
release_context.json today). application_security/infrastructure_security
currently only have FILE-level provenance (when release_context.json/
infra_context.json themselves were last built) — true per-tool
provenance for codeql/sonarcloud/gitguardian/snyk/kube-linter/checkov/
terraform-validate doesn't exist yet (no timestamp capture in those
workflows currently, only scan_status success/failure). Not invented
here — Python owns facts, not synthesized ones. Closing that gap is a
separate, larger task (timestamp capture in backend-ci.yaml etc.), out of
scope for this script.

commits_behind is best-effort via `git rev-list --count` if this script
is run from within a checkout that has both commits in history (true in
the real GH Actions context once wired up) — gracefully degrades to null
with an explanatory note if git isn't available or either SHA isn't
reachable (true when testing standalone, e.g. against archived JSON
artifacts with no matching local checkout).

Usage:
    compose_release_context.py --output final_release_context.json \\
        --release-context release_context.json \\
        --infra-context infra_context.json
"""
import argparse
import json
import subprocess
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_release_context import (
    assign_domain,
    compute_release_statistics,
    DOMAIN_ORDER,
    SEVERITY_RANK,
    load_json,
)

SCHEMA_VERSION = "1.0.0"

# The real set of values actually produced today, confirmed by grepping
# every workflow and builder — not a speculative larger enum. STALE/
# NOT_EXECUTED deliberately excluded: STALE would duplicate the job
# already done by provenance's days_stale fields, and nothing currently
# has a code path that needs to distinguish NOT_EXECUTED from SKIPPED.
SCAN_STATUS_MAP = {
    "success": "SUCCESS",
    "failed": "FAILED",
    "skipped": "SKIPPED",
    "not_configured": "NOT_CONFIGURED",
}


def normalize_scan_status(scan_status):
    """Uppercases/validates scan_status values into the fixed enum, once,
    centrally — not by editing the `echo "status=success"` lines across
    every workflow YAML (infra-security-scan.yaml, runtime-security-scan.
    yaml, etc.), the same way SEVERITY_NORMALIZATION already centralizes
    per-tool spelling differences rather than touching every normalizer.
    This is also the cheapest possible moment to make this change:
    run_security_analysis.py has never consumed this data, so there's no
    existing consumer whose assumptions about the old lowercase strings
    could break."""
    normalized = {}
    for domain_key, tools in (scan_status or {}).items():
        normalized[domain_key] = {}
        for tool, value in tools.items():
            mapped = SCAN_STATUS_MAP.get(value)
            if mapped is None:
                print(
                    f"WARNING: unrecognized scan_status value {value!r} for "
                    f"{domain_key}.{tool} — add it to SCAN_STATUS_MAP in "
                    f"compose_release_context.py. Leaving as-is.",
                    file=sys.stderr,
                )
                mapped = value
            normalized[domain_key][tool] = mapped
    return normalized


def derive_verification_status(supply_chain_entry):
    """Resolves a real, confirmed bug, not just adding a field for its own
    sake — release-readiness.yaml's actual supply_chain producer has:
        "image_signed": "unknown" if not verified else True
    a genuinely mixed-type field (string OR bool depending on the cosign
    exit code), confirmed by reading that workflow directly, not assumed.
    The mix isn't an oversight: cosign's failure mode can't cleanly
    distinguish "never signed" from "signed but verification failed"
    without parsing error text, which that workflow deliberately doesn't
    do — real three-state uncertainty a boolean can't represent cleanly.

    Added alongside image_signed/signature_verified, not replacing them —
    removing existing fields is a v1.1 deprecation, not a v1.0 addition."""
    if supply_chain_entry is None:
        return "SKIPPED"
    signed = supply_chain_entry.get("image_signed")
    verified = supply_chain_entry.get("signature_verified")
    if verified is True:
        return "SUCCESS"
    if signed == "unknown" or verified is None:
        return "UNKNOWN"
    if verified is False:
        return "FAILED"
    return "UNKNOWN"


def try_commits_behind(older_sha, newer_sha):
    """Best-effort only — see module docstring's commits_behind note."""
    try:
        result = subprocess.run(
            ["git", "rev-list", "--count", f"{older_sha}..{newer_sha}"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return int(result.stdout.strip())
    except (FileNotFoundError, ValueError, subprocess.TimeoutExpired):
        pass
    return None


def build_provenance(release_ctx, infra_ctx):
    app_release = release_ctx.get("release", {})
    infra_release = infra_ctx.get("release", {})
    app_version = app_release.get("version")
    infra_version = infra_release.get("version")
    version_matches = app_version == infra_version

    commits_behind = None
    commits_behind_note = (
        "Not computed — versions match." if version_matches else
        "git history lookup unavailable or SHAs not reachable from this checkout."
    )
    if not version_matches and app_version and infra_version:
        cb = try_commits_behind(infra_version, app_version)
        if cb is not None:
            commits_behind = cb
            commits_behind_note = (
                f"infra_context.json is {cb} commit(s) behind release_context.json "
                f"(via git rev-list)."
            )

    # Per-workflow real source commits, when available — added 2026-06-27
    # alongside the latest-successful-run fallback in release-readiness.yaml
    # (backend-ci.yaml/frontend-ci.yaml/app-security-scan-*.yaml only
    # re-run on backend/**/frontend/** changes, so a pure scripts/ or
    # workflow-only commit won't have a matching run — the same staleness
    # reality infrastructure_security already accounts for). Falls back to
    # the old file-level-only note for any release_context.json built
    # before this field existed — backward compatible, not a hard
    # requirement.
    app_sec_provenance = release_ctx.get("app_sec_provenance") or {}
    if app_sec_provenance:
        any_fallback = any(not v.get("exact_match", True) for v in app_sec_provenance.values())
        application_security_provenance = {
            "per_workflow": app_sec_provenance,
            "any_used_fallback_commit": any_fallback,
            "note": (
                "Per-workflow real source commit, since backend-ci.yaml/frontend-ci.yaml/"
                "app-security-scan-*.yaml only re-run on backend/**/frontend/** changes — "
                "exact_match: false means that workflow's latest successful run came from "
                "a different commit than this release, surfaced here rather than silently "
                "assumed current. Still file-level only within each workflow — no per-tool "
                "(codeql vs sonarcloud vs gitguardian vs snyk) timestamps exist yet."
            ),
        }
    else:
        application_security_provenance = {
            "source_version": app_version,
            "source_generated_at": app_release.get("generated_at"),
            "note": (
                "File-level only — per-tool timestamps for codeql/sonarcloud/"
                "gitguardian/snyk aren't tracked yet (scan_status has success/"
                "failure, not when each tool last ran). This reflects when "
                "release_context.json itself was last built. No app_sec_provenance "
                "data available — this release_context.json predates that field, or "
                "release-readiness.yaml's download step didn't produce it."
            ),
        }

    return {
        "repository": app_release.get("repository"),
        "application_security": application_security_provenance,
        "infrastructure_security": {
            "source_version": infra_version,
            "source_generated_at": infra_release.get("generated_at"),
            "version_matches_application_security": version_matches,
            "commits_behind": commits_behind,
            "commits_behind_note": commits_behind_note,
            "note": (
                "File-level only — per-tool timestamps for kube-linter/checkov/"
                "terraform-validate aren't tracked yet. infra-security-scan.yaml "
                "only triggers on helm/**, terraform/** changes, so this version "
                "differing from application_security's is the EXPECTED normal "
                "case, not an error — see this script's MERGE VALIDATION note."
            ),
        },
        # Already genuinely per-tool — these three jobs are each
        # independently schedulable, so collapsing them into one
        # "runtime_security" timestamp would lose real information.
        "runtime_security": {
            "zap": release_ctx.get("dast_scan_metadata"),
            "kyverno": release_ctx.get("kyverno_scan_metadata"),
            "kubearmor": release_ctx.get("kubearmor_scan_metadata"),
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", required=True)
    parser.add_argument("--release-context", required=True)
    parser.add_argument("--infra-context", required=True)
    args = parser.parse_args()

    release_ctx = load_json(args.release_context, None)
    infra_ctx = load_json(args.infra_context, None)
    if release_ctx is None or infra_ctx is None:
        print(
            f"FATAL: could not load one or both input files "
            f"({args.release_context!r}, {args.infra_context!r}). Cannot compose "
            f"a final ReleaseContext from a missing input — this is a hard failure, "
            f"not something to default around.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Hard validation: repository must match. This is the ONE thing that
    # should never differ — see module docstring for why version
    # differing is the opposite case (expected, not an error).
    app_repo = release_ctx.get("release", {}).get("repository")
    infra_repo = infra_ctx.get("release", {}).get("repository")
    if app_repo != infra_repo:
        print(
            f"FATAL: repository mismatch — release_context.json says {app_repo!r}, "
            f"infra_context.json says {infra_repo!r}. This means the wrong artifact "
            f"was passed in, not a staleness issue — refusing to silently produce an "
            f"inconsistent ReleaseContext.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Merge findings: concatenation, not re-grouping — see module
    # docstring for why this is verified safe, not just convenient.
    merged_findings = list(release_ctx.get("findings", [])) + list(infra_ctx.get("findings", []))

    # Domain assignment happens HERE, once, centrally — not duplicated
    # per-normalizer or per-builder.
    for f in merged_findings:
        f["domain"] = assign_domain(f)

    # Stable sort for human readability — domain_order -> severity_rank
    # (highest first) -> category -> tool. The AI agent should still treat
    # this as one unified evidence set and actively correlate across
    # domains; this ordering is for human/report consumption, not a signal
    # that reasoning should be domain-sequential.
    merged_findings.sort(
        key=lambda f: (
            DOMAIN_ORDER.get(f["domain"], 99),
            -SEVERITY_RANK.get((f.get("severity") or "unknown").lower(), -1),
            f.get("category") or "",
            f.get("tool") or "",
        )
    )

    # Recomputed fresh on the full merged set — NOT trusting either
    # builder's own partial release_statistics, per the agreed design.
    release_statistics = compute_release_statistics(merged_findings)

    # Plain dict union — verified safe, see module docstring.
    remediation_guide = {**release_ctx.get("remediation_guide", {}), **infra_ctx.get("remediation_guide", {})}

    # scan_status: also a plain union — verified safe, the two inputs use
    # disjoint top-level keys (backend/frontend/deployed-app vs.
    # infrastructure/terraform), confirmed by inspecting both builders'
    # actual default_scan_status dicts.
    scan_status = normalize_scan_status({**release_ctx.get("scan_status", {}), **infra_ctx.get("scan_status", {})})

    components = list(release_ctx.get("release", {}).get("components", [])) + \
        list(infra_ctx.get("release", {}).get("components", []))

    # Additive: verification_status alongside the existing image_signed/
    # signature_verified fields — see derive_verification_status' docstring
    # for the real bug this resolves.
    supply_chain = release_ctx.get("supply_chain")
    if supply_chain:
        for component_entry in supply_chain.values():
            if isinstance(component_entry, dict):
                component_entry["verification_status"] = derive_verification_status(component_entry)

    final_context = {
        "schema_version": SCHEMA_VERSION,
        "release": {
            # Deliberately app's version, not infra's — see provenance
            # for the full staleness picture instead of picking a winner
            # silently here. application_security's version is the more
            # natural "what release is this" anchor since it's tied to
            # the actual code being shipped, not the cluster config.
            "version": release_ctx.get("release", {}).get("version"),
            "repository": app_repo,
            "components": components,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "provenance": build_provenance(release_ctx, infra_ctx),
        "findings": merged_findings,
        "remediation_guide": remediation_guide,
        "scan_status": scan_status,
        "release_statistics": release_statistics,
        # Aggregate, non-finding sections — passed through unchanged from
        # release_context.json. Not represented as finding domains, per
        # the agreed design (supply chain stays an aggregate section).
        "sbom_summary": release_ctx.get("sbom_summary"),
        "dependency_summary": release_ctx.get("dependency_summary"),
        "supply_chain": supply_chain,
        "signal_availability": release_ctx.get("signal_availability"),
        "schema_validation": infra_ctx.get("schema_validation"),
        "terraform_validation": infra_ctx.get("terraform_validation"),
    }

    with open(args.output, "w") as f:
        json.dump(final_context, f, indent=2)

    print(
        f"Composed final ReleaseContext: {len(release_ctx.get('findings', []))} app/runtime + "
        f"{len(infra_ctx.get('findings', []))} infra/terraform = {len(merged_findings)} total findings "
        f"-> {args.output}"
    )
    print(f"  by_domain: {release_statistics['by_domain']}")
    if app_repo == infra_repo and release_ctx.get("release", {}).get("version") != infra_ctx.get("release", {}).get("version"):
        print(
            f"  NOTE: version mismatch is expected (see provenance.infrastructure_security) — "
            f"not a failure.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()