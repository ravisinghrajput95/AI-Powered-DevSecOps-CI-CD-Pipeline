# Security Policy

## ⚠️ Read this first: most "vulnerabilities" here are intentional

This repository contains **CloudCart**, a deliberately vulnerable application
used as a test fixture for the security pipeline. SQL injection, stored XSS,
command injection, SSRF, path traversal, hardcoded credentials, outdated base
images and misconfigured Terraform are all **planted on purpose** and
documented in [README.md](README.md#intentional-vulnerabilities).

They are the pipeline's input data. Removing them would silently delete the
findings the whole project exists to demonstrate — the test suites in
`backend/tests/` and `frontend/src/__test__/` assert several of them are
*still present* for exactly this reason.

**Please do not open reports for anything in this list.** They are known,
deliberate, and load-bearing.

## What IS in scope

Report anything that makes the **security pipeline itself** untrustworthy —
the code under `scripts/`, `.github/workflows/`, `helm/`, `policies/` and
`tests/`. Concretely:

| In scope | Why it matters |
|---|---|
| A scanner failing while reporting success | A release decision built on "0 findings" that were never collected |
| Findings silently dropped between a scanner and the report | Same as above, harder to notice |
| The AI citing a `finding_id` that does not exist | Breaks the evidence contract the report rests on |
| Schema validation passing on a non-conforming artifact | Downstream consumers trust the contract |
| Secrets leaking into artifacts, logs or committed reports | Real exposure, not simulated |
| Supply-chain gaps — unpinned actions, unverified signatures, a bypassable cosign gate | The deploy gate is fail-closed and must stay that way |
| Privilege escalation in CI — a workflow obtaining more GCP access than its job needs | Real cloud credentials are involved |

This class of bug has occurred here before and is taken seriously: five
separate mechanisms once produced silently incomplete data behind green
checkmarks (expired credentials recorded as successful scans, a scanner-side
severity threshold discarding 1,341 findings, a shell function leaking a
warning into its return value, and a working tool reported as
`NOT_CONFIGURED`). `tests/test_workflow_invariants.py` now guards each one.

## Reporting

Open a **[GitHub Security Advisory](../../security/advisories/new)** for
anything in the in-scope table. That keeps the report private until a fix
exists.

For non-sensitive pipeline bugs, a normal issue is fine and preferred — it is
easier to discuss in the open.

Please include:

- Which component (`scripts/`, a specific workflow, a chart, a policy)
- What the pipeline reported versus what was actually true
- A run ID or artifact if the behaviour appeared in CI

**Response expectation:** this is a personal portfolio project maintained by
one person, not a funded product. Best effort, typically within a week. There
is no bug bounty.

## Credentials and secrets

Every credential visible in this repository is fake and planted — the AWS
key, Stripe key, GitHub token and database passwords in `backend/config.py`,
`backend/Dockerfile` and the Helm values files exist so GitGuardian has
something real to detect.

Real credentials live only in GitHub Actions secrets and are never committed.
If you believe an actual credential has leaked, treat it as in scope and use
a private security advisory.

## Supported versions

This project is a demonstrator, not a released library. Only `main` is
maintained; there are no patched release branches.
