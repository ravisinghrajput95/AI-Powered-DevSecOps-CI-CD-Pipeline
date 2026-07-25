# Sample Release Intelligence Report

A **real, unedited** report produced by this pipeline. Committed because
GitHub Actions artifacts expire, so anyone visiting this repository later
would otherwise have no way to see what the AI Release Intelligence Engine
actually outputs.

| | |
|---|---|
| **Report ID** | `fc3ff0dc9c44a2bc` |
| **Generated** | 2026-07-25 |
| **Release** | `f083f2d` |
| **Model** | `claude-haiku-4-5` |
| **Verdict** | `DO_NOT_APPROVE` — health CRITICAL, confidence LOW |
| **Findings** | 239 grouped (544 occurrences) across 4 domains, 8 tools |

## Files

| File | What it is |
|---|---|
| [`sample/release_report.md`](sample/release_report.md) | The rendered report — **start here** |
| [`sample/release_report.html`](sample/release_report.html) | Same report, styled |
| [`sample/executive_report.json`](sample/executive_report.json) | The AI's structured output, schema-validated |
| [`sample/final_release_context.json`](sample/final_release_context.json) | The input the model reasoned over |

Both JSON files are the actual contracts, not illustrations:
`executive_report.json` conforms to `scripts/executive_report_schema.py` and
`final_release_context.json` to `scripts/release_context_schema.py`. Every
`finding_id` cited in the report was verified to exist in the context before
the artifact was written — a check that exists because an early run once
cited the same finding twice with a transposed id.

## What it demonstrates

**Cross-tool correlation.** The report links Kyverno's live admission
failures to Checkov's static IaC findings, and CodeQL's injection findings
to SonarCloud's independently. No single scanner produces those statements —
that correlation is the reason this pipeline exists.

**Honest gaps.** `scan_status.deployed-app.kubearmor` is `NO_SIGNAL`, and the
model surfaces it in `assumptions_and_unknowns` rather than treating an empty
runtime domain as a clean one. KubeArmor runs and enforces but produces no
policy alerts in this environment (see
[`../helm/bootstrap/README.md`](../helm/bootstrap/README.md) for the
investigation). `NO_SIGNAL` exists precisely so "the tool found nothing"
cannot be mistaken for "there is nothing to find".

The model also flagged, unprompted, that the infrastructure scan was 28 days
stale relative to the release — from the provenance block, which records
which commit each upstream scan actually came from.

## Caveats, stated rather than hidden

- **Generated on `claude-haiku-4-5`, not the default `claude-sonnet-4-6`**,
  under a hard API budget. Haiku failed schema validation on its first
  attempt (a risk-theme string exceeded max length) and succeeded on the
  built-in corrective retry. Sonnet runs the same day produced 7
  cross-domain correlations against Haiku's 6, with longer reasoning chains.
  A Sonnet report is the better artifact if you regenerate this.
- **Every finding is real and intentional.** CloudCart is a deliberately
  vulnerable application; the SQL injection, XSS, command injection,
  hardcoded secrets, outdated base images and misconfigured Terraform are all
  planted on purpose. `DO_NOT_APPROVE` is the correct verdict and the
  pipeline working, not a bug.
- **`container_security` shows 57 findings from 1,504 scanned.** Container
  scans run with no severity threshold, so the raw artifacts hold everything;
  `--container-severity-floor` (default `high`) decides what the model
  reasons over. Lower it via the workflow input to widen the report without
  re-running a single scan.

## Regenerating

```bash
gh workflow run release-readiness.yaml -f run_ai_analysis=true
```

Leave `run_ai_analysis` unset to build `final_release_context.json` only —
free, no API call, and enough to verify the data plumbing.
