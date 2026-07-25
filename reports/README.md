# Sample Release Intelligence Report

A **real** report produced by this pipeline. Committed because GitHub Actions
artifacts expire, so anyone visiting this repository later would otherwise
have no way to see what the AI Release Intelligence Engine actually outputs.

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

## ⚠️ Placeholders

**These files are not byte-identical to the pipeline's output.** Two
substitutions were made before committing:

1. The real GCP project ID → `<GCP_PROJECT_ID>` (344 places), appearing
   throughout as Artifact Registry image paths:

   ```
   us-central1-docker.pkg.dev/<GCP_PROJECT_ID>/cloudcart-frontend/cloudcart-frontend:<sha>
   ```

2. The cluster's LoadBalancer IP → `<CLUSTER_IP>` (34 places), appearing as
   the ZAP scan target:

   ```
   ["http://<CLUSTER_IP>/", "http://<CLUSTER_IP>/robots.txt", ...]
   ```

   That address pointed at a live, internet-facing instance of a deliberately
   vulnerable application. Publishing it in a public repository handed anyone
   reading this a working target, which flatly contradicts the warning at the
   top of the main README. It should never have been committed unscrubbed.

Those two substitutions are the **only** modifications. Findings, severities,
correlations, verdict, reasoning and finding-id citations are all exactly as
generated. If you regenerate this report yourself, expect your own project id
and your own cluster address in those places.

Nothing else is redacted. The pipeline's normalizers record rule ids and
locations rather than secret values, so no credential — including the AWS,
Stripe and GitHub keys deliberately planted in this codebase — appears in the
output.

## What it demonstrates

**Cross-tool correlation.** The report links Kyverno's live admission
failures to Checkov's static IaC findings, and CodeQL's injection findings to
SonarCloud's independently. No single scanner produces those statements —
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

The structured `executive_report.json` and `final_release_context.json` are
produced as workflow artifacts on every run. They are deliberately **not**
committed here — they are large, and the context file carries the same
project id throughout.
