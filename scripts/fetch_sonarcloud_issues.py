#!/usr/bin/env python3
"""
Polls SonarCloud's background task API until analysis completes, then
fetches issues via api/issues/search and normalizes into the shared
schema: {tool, severity, rule_id, message, file, start_line, end_line}

SonarCloud's analysis runs asynchronously server-side after the scanner
step finishes. This script reads the task ID from .scannerwork/report-task.txt
(written by the scanner action) and polls api/ce/task before querying issues,
to avoid fetching stale results from a previous scan.

NOTE: SonarCloud's API has two severity representations in parallel use:
  - a flat `severity` field (legacy, e.g. "MAJOR", "BLOCKER")
  - a newer `impacts: [{softwareQuality, severity}]` array
This script checks impacts[] first and falls back to the flat field, since
both are seen in current real-world API responses.

Usage:
    fetch_sonarcloud_issues.py <output.json> <project_key> <sonar_token> [report_task_path]
"""
import json
import sys
import time
import os
import urllib.request
import urllib.parse
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from classify_finding import classify, build_line_field

SONAR_API_BASE = "https://sonarcloud.io/api"
MAX_POLL_ATTEMPTS = 30
POLL_INTERVAL_SECONDS = 10


def api_get(path, params, token):
    url = f"{SONAR_API_BASE}{path}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"ERROR: HTTP {e.code} calling {path}: {body}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"ERROR calling {path}: {e}", file=sys.stderr)
        return None


def read_task_id(report_task_path):
    """report-task.txt is a flat key=value file written by the scanner."""
    try:
        with open(report_task_path) as f:
            for line in f:
                if line.startswith("ceTaskId="):
                    return line.strip().split("=", 1)[1]
    except FileNotFoundError:
        print(f"WARNING: {report_task_path} not found — cannot poll task status.", file=sys.stderr)
    return None


def wait_for_task(task_id, token):
    if not task_id:
        print("No task ID available — skipping poll, fetching issues immediately (may be stale).", file=sys.stderr)
        return False

    for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
        data = api_get("/ce/task", {"id": task_id}, token)
        if data is None:
            return False

        status = data.get("task", {}).get("status", "UNKNOWN")
        print(f"Attempt {attempt}/{MAX_POLL_ATTEMPTS}: task status = {status}")

        if status == "SUCCESS":
            return True
        if status in ("FAILED", "CANCELED"):
            print(f"ERROR: SonarCloud analysis task ended with status {status}", file=sys.stderr)
            return False

        time.sleep(POLL_INTERVAL_SECONDS)

    print("ERROR: timed out waiting for SonarCloud analysis task to complete.", file=sys.stderr)
    return False


def get_severity(issue):
    impacts = issue.get("impacts", [])
    if isinstance(impacts, list) and impacts:
        sev = impacts[0].get("severity")
        if sev:
            return sev
    return issue.get("severity", "UNKNOWN")


def normalize_issues(issues):
    findings = []
    for issue in issues:
        text_range = issue.get("textRange", {})
        severity = get_severity(issue)
        rule_id = issue.get("rule", "unknown")
        message = issue.get("message", "")

        category, confidence, recommendation = classify("sonarcloud", severity, rule_id, message)

        findings.append({
            "tool": "sonarcloud",
            "severity": severity,
            "category": category,
            "rule_id": rule_id,
            "message": message,
            "file": issue.get("component", "unknown"),
            "line": build_line_field(text_range.get("startLine"), text_range.get("endLine")),
            "confidence": confidence,
            "recommendation": recommendation,
        })
    return findings


def fetch_all_issues(project_key, token):
    all_issues = []
    page = 1
    page_size = 500
    while True:
        data = api_get(
            "/issues/search",
            {
                "componentKeys": project_key,
                "resolved": "false",
                "ps": page_size,
                "p": page,
            },
            token,
        )
        if data is None:
            break

        issues = data.get("issues", [])
        all_issues.extend(issues)

        total = data.get("total", len(issues))
        if page * page_size >= total or not issues:
            break
        page += 1

    return all_issues


def main():
    if len(sys.argv) < 4:
        print(
            "Usage: fetch_sonarcloud_issues.py <output.json> <project_key> <sonar_token> [report_task_path]",
            file=sys.stderr,
        )
        sys.exit(1)

    output_path = sys.argv[1]
    project_key = sys.argv[2]
    token = sys.argv[3]
    report_task_path = sys.argv[4] if len(sys.argv) > 4 else ".scannerwork/report-task.txt"

    task_id = read_task_id(report_task_path)
    wait_for_task(task_id, token)

    issues = fetch_all_issues(project_key, token)
    findings = normalize_issues(issues)

    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"Normalized {len(findings)} SonarCloud findings -> {output_path}")


if __name__ == "__main__":
    main()
