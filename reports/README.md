# Sample Release Intelligence Report

A **real** report produced by this pipeline. Committed because GitHub Actions
artifacts expire, so anyone visiting this repository later would otherwise
have no way to see what the AI Release Intelligence Engine actually outputs.

| | |
|---|---|
| **Report ID** | `d6af1576eadedf6c` |
| **Generated** | 2026-07-25 |
| **Release** | `2382597` |
| **Model** | `claude-sonnet-4-6` |
| **Verdict** | `DO_NOT_APPROVE` — health CRITICAL, deployment confidence LOW |
| **Findings** | 240 across 4 domains, 9 tools |
| **Correlations** | 7 cross-domain |
| **Scan coverage** | **19 of 19 scanners `SUCCESS`** |

Domain split: `application_security` 127, `container_security` 57,
`infrastructure_security` 32, `runtime_security` 24.

Every scanner across all five components reported `SUCCESS` for this run — no
`NOT_CONFIGURED`, no `NO_SIGNAL`, no `FAILED`. That had never happened before:
earlier reports carried an unmeasured runtime domain, an uninstrumented syft,
or a container scan whose status was hardcoded.

## Files

| File | What it is |
|---|---|
| [`sample/release_report.md`](sample/release_report.md) | The rendered report — **start here** |
| [`sample/release_report.html`](sample/release_report.html) | Same report, styled |

## ⚠️ Placeholder

**These files are not byte-identical to the pipeline's output.** The real GCP
project ID was replaced with `<GCP_PROJECT_ID>` (8 occurrences, HTML only —
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

**Cross-tool correlation.** The lead correlation — *"Workload Identity
disabled + Owner IAM + root containers = full project blast radius"* — spans
all three of `runtime_security`, `infrastructure_security` and
`application_security`, citing **9 findings** from Checkov's static Terraform
analysis and Kyverno's live admission results together. It concludes that a
container process which escalates reaches the GCE metadata server and turns a
breakout into full project compromise. One static tool, one runtime tool, nine
citations. No single scanner produces that sentence.

**Runtime evidence is real, not static analysis.** Kyverno's violations are
live admission results from the deployed cluster, scanned 0 days stale, and
the report distinguishes them from configuration review explicitly.

**Honest gaps.** `assumptions_and_unknowns` carries 10 entries: reachability,
exploitability, business impact and internet exposure are **not collected**,
and supply-chain verification returned UNKNOWN for both images.

**Provenance is exact.** Every upstream scan ran at `2382597`, the same commit
this report assesses — `any_used_fallback_commit` is `false`, the
infrastructure scan's version matches, and all three runtime scanners report
`days_stale: 0`. Earlier reports carried fallback matching or a 28-day-stale
infrastructure scan, and said so; this one has nothing of the kind to
disclose, which is why the assumptions list is two entries shorter.

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
- **Those KubeArmor findings are simulated, and the prompt now says so.** The
  runtime scan exercises its own audit policies during the capture window (the
  same active-probing model ZAP uses for DAST), so a shell-execution alert is
  the pipeline testing its detection, not an observed intrusion. See
  [`../helm/bootstrap/README.md`](../helm/bootstrap/README.md).

  This caveat exists because an earlier run got it wrong. Given the same
  findings without that context, the model wrote that the shell execution
  "warrants investigation as a potential active compromise indicator" — a
  reasonable inference from the evidence it had, and false. That report was
  discarded rather than committed, and `scripts/system_prompt.md` now states
  the provenance of KubeArmor findings explicitly. Kyverno and ZAP are
  deliberately excluded from the caveat and keep their full weight.
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
