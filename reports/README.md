# Sample Release Intelligence Report

A **real** report produced by this pipeline. Committed because GitHub Actions
artifacts expire, so anyone visiting this repository later would otherwise
have no way to see what the AI Release Intelligence Engine actually outputs.

| | |
|---|---|
| **Report ID** | `2972549035486c62` |
| **Generated** | 2026-07-25 |
| **Release** | `0b5819a` |
| **Model** | `claude-sonnet-4-6` |
| **Verdict** | `DO_NOT_APPROVE` — health CRITICAL, deployment confidence LOW |
| **Findings** | 241 across 4 domains, 9 tools |
| **Correlations** | 7 cross-domain |

Domain split: `application_security` 128, `container_security` 57,
`infrastructure_security` 32, `runtime_security` 24.

## Files

| File | What it is |
|---|---|
| [`sample/release_report.md`](sample/release_report.md) | The rendered report — **start here** |
| [`sample/release_report.html`](sample/release_report.html) | Same report, styled |

## ⚠️ Placeholder

**These files are not byte-identical to the pipeline's output.** The real GCP
project ID was replaced with `<GCP_PROJECT_ID>` (16 occurrences, HTML only —
Artifact Registry image paths). That substitution is the **only**
modification. Findings, severities, correlations, verdict, reasoning and
finding-id citations are exactly as generated.

Nothing else is redacted. The normalizers record rule ids and locations rather
than secret values, so no credential — including the AWS, Stripe and GitHub
keys deliberately planted in this codebase — appears in the output.

> An earlier committed report also contained the cluster's live LoadBalancer
> IP in 34 places, as the ZAP scan target, while that address was serving a
> deliberately vulnerable app on the public internet. It was scrubbed, and
> `tests/test_docs_accuracy.py` now fails if any committed report contains a
> live host address.

## What it demonstrates

**Cross-tool correlation.** The lead correlation joins Terraform's disabled
Workload Identity (Checkov) to project-scope Owner IAM and to SSRF findings in
application code — concluding that a container escape or SSRF from any pod
reaches the metadata server and yields a project-Owner token. Five citations,
three domains, three tools. No single scanner produces that sentence.

**Runtime evidence is real, not static analysis.** Kyverno's privilege-
escalation violations are live admission results from the deployed cluster,
and the report says so explicitly rather than presenting them as config
review.

**Honest gaps.** `assumptions_and_unknowns` records that reachability,
exploitability, business impact and internet exposure are **not collected**,
that supply-chain verification returned UNKNOWN for both images, and —
unprompted — that the infrastructure scan ran 28 days before this release,
which the model read off the provenance block.

## Caveats, stated rather than hidden

- **Every finding is real and intentional.** CloudCart is deliberately
  vulnerable; the SQL injection, XSS, command injection, hardcoded secrets,
  outdated base images and misconfigured Terraform are planted on purpose.
  `DO_NOT_APPROVE` is the correct verdict and the pipeline working.
- **KubeArmor contributed 2 findings that the model did not cite.** They are
  present in `final_release_context.json`, correctly typed as
  `runtime_security`, and available to the model, which judged two shell-exec
  audit events less decision-relevant than confirmed OS-command injection.
  That is the reasoning layer doing its job, not a plumbing failure — but it
  means the runtime domain's weight in this report comes from Kyverno and ZAP.
- **Those KubeArmor findings are simulated.** The runtime scan exercises the
  audit policies during its capture window (the same active-probing model ZAP
  uses for DAST), so a shell-execution alert reflects the pipeline's own test
  action, not an observed intrusion. See
  [`../helm/bootstrap/README.md`](../helm/bootstrap/README.md).
- **`container_security` shows 57 findings.** Container scans run with no
  severity threshold, so raw artifacts hold everything;
  `--container-severity-floor` (default `high`) decides what the model reasons
  over. Lower it via the workflow input to widen the report without re-running
  a scan.

## Regenerating

```bash
gh workflow run release-readiness.yaml -f run_ai_analysis=true -f model=claude-sonnet-4-6
```

Leave `run_ai_analysis` unset to build `final_release_context.json` only —
free, no API call, and enough to verify the data plumbing.

To see the renderers and citation resolution with no cluster and no API key at
all, use the committed fixtures:

```bash
python3 scripts/demo_report.py --list
```

The structured `executive_report.json` and `final_release_context.json` are
produced as workflow artifacts on every run. They are deliberately **not**
committed — they are large, and the context file carries the project id
throughout.
