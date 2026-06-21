#!/usr/bin/env python3
"""
Normalizes a ZAP Baseline Scan JSON report (produced via the -J flag, e.g.
`zap-baseline.py ... -J zap-report.json`) into the shared schema:
{tool, severity, category, type, rule_id, message, file, line, confidence, recommendation}

VERIFIED SCHEMA (ZAP's JSON report format has been stable for years):
{
  "site": [
    {
      "@name": "http://example.com",
      "alerts": [
        {
          "pluginid": "10038",
          "alert": "Content Security Policy (CSP) Header Not Set",
          "riskcode": "1",      # 0=Informational, 1=Low, 2=Medium, 3=High
          "confidence": "2",    # 0=False Positive, 1=Low, 2=Medium, 3=High, 4=User Confirmed
          "desc": "...",
          "solution": "...",
          "instances": [
            {"uri": "http://example.com/", "method": "GET", "param": "", "evidence": ""}
          ]
        }
      ]
    }
  ]
}

DESIGN NOTE: this is a DAST scan against a live deployed app, not a
component-scoped tool like the others — there's no clean backend/frontend
split, since both are served from the same public target. One finding is
emitted per affected URI (not one finding per alert with a bundled URL
list) so that build_release_context.py's existing occurrence-grouping
logic collapses multi-instance alerts into one entry with a `locations`
list automatically — the same mechanism already used for GitGuardian's
multi-file secrets and SonarCloud's multi-occurrence rule_ids. No new
aggregation logic needed for this tool.

NOTE: classify_finding.py's "missing-security-headers"/"insecure-cookie"
categories were added proactively based on ZAP's well-known standard alert
catalog, but have not yet been validated against a real scan of this app.
Check stderr for "unmatched rule_id" warnings on the first real run.

ZAP's own `confidence` field (false-positive vs. user-confirmed) is a more
meaningful signal than anything classify_confidence() would derive from
severity, so it's used directly here instead.

Usage:
    normalize_zap.py <output.json> <zap_report.json>
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from classify_finding import classify_category, classify_recommendation
from classify_finding import TYPE_BY_CATEGORY, DEFAULT_TYPE

RISKCODE_SEVERITY = {
    "0": "informational",
    "1": "low",
    "2": "medium",
    "3": "high",
}

ZAP_CONFIDENCE_MAP = {
    "0": "low",   # false positive
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "high",  # user confirmed
}


def normalize_alert(alert, site_name):
    # alertRef distinguishes between variants of the same plugin (e.g. ZAP's
    # three Cross-Origin-*-Policy header checks — Embedder/Opener/Resource —
    # all share pluginid "90004" and are only told apart by alertRef
    # "90004-1"/"90004-2"/"90004-3"). Using pluginid alone here would merge
    # three genuinely distinct findings into one once build_release_context.py
    # groups by rule_id — confirmed by inspecting a real scan's output, where
    # pluginid 90004 covered three different header checks. alertRef falls
    # back cleanly to the plain pluginid string when there's only one variant.
    rule_id = str(alert.get("alertRef") or alert.get("pluginid", "unknown"))
    message = alert.get("alert") or alert.get("name", "")
    severity = RISKCODE_SEVERITY.get(str(alert.get("riskcode", "0")), "informational")
    confidence = ZAP_CONFIDENCE_MAP.get(str(alert.get("confidence", "0")), "low")

    category = classify_category(rule_id, message)
    type_ = TYPE_BY_CATEGORY.get(category, DEFAULT_TYPE)
    recommendation = classify_recommendation(category)

    instances = alert.get("instances", [])
    uris = [inst.get("uri", site_name) for inst in instances] or [site_name]

    findings = []
    for uri in uris:
        findings.append({
            "tool": "zap",
            "severity": severity,
            "category": category,
            "type": type_,
            "rule_id": rule_id,
            "message": message,
            "file": uri,
            "line": None,
            "confidence": confidence,
            "recommendation": recommendation,
        })
    return findings


def normalize_report(report_path):
    findings = []
    try:
        with open(report_path) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"WARNING: could not read {report_path}: {e}", file=sys.stderr)
        return findings

    for site in data.get("site", []):
        site_name = site.get("@name", "unknown")
        for alert in site.get("alerts", []):
            findings.extend(normalize_alert(alert, site_name))

    return findings


def main():
    if len(sys.argv) != 3:
        print("Usage: normalize_zap.py <output.json> <zap_report.json>", file=sys.stderr)
        sys.exit(1)

    output_path = sys.argv[1]
    report_path = sys.argv[2]

    findings = normalize_report(report_path)

    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"Normalized {len(findings)} ZAP findings -> {output_path}")


if __name__ == "__main__":
    main()