# CLAUDE.md — AI-Powered DevSecOps CI/CD Pipeline

## Project Overview
This project builds an AI-powered DevSecOps CI/CD pipeline using GitHub Actions, Kubernetes, and Claude as the AI agent framework. The pipeline runs against **CloudCart** — an intentionally vulnerable 3-tier ecommerce application — to demonstrate real-world AI-assisted security findings, cross-tool exploitability analysis, and automated remediation.

## Target Application — CloudCart
- **Type**: Intentionally vulnerable 3-tier ecommerce app (monorepo)
- **Name**: CloudCart
- **Frontend**: React
- **Backend**: Flask (Python)
- **Database**: PostgreSQL
- **Features**: Login, Products, Cart, Orders, Reviews, Admin
- **Vulnerability approach**: Discovered organically by pipeline tools — not pre-catalogued. AI agents explain findings in plain English and suggest remediations.
- **Repo structure**:
  ```
  /frontend            # React app (CloudCart UI)
  /backend             # Flask app (CloudCart API)
  /helm                # Helm charts:
                       #   bootstrap/  cluster prerequisites — install FIRST
                       #   postgresql/ database + schema/seed ConfigMaps
                       #   cloudcart/  the application (backend + frontend subcharts)
  /terraform           # Kubernetes cluster infrastructure (intentionally misconfigured for Checkov)
  /policies            # kyverno/ (19 ClusterPolicies), kubearmor/ (8 policies)
  /scripts             # normalizers, context builders, AI engine, renderers
  /tests               # 507-test suite for scripts/ (golden + real-world fixtures)
  /monitoring          # Prometheus/Grafana config
  /.github/workflows   # 14 CI/CD + security workflows
  ```

  Artifacts (SBOMs, normalized findings, release context, executive report)
  are produced as workflow artifacts rather than committed directories —
  there is no /sbom or /security tree.

---

## Human-in-the-Loop Policy
Not every finding blocks the pipeline. Severity determines action:

| Severity | AI Action | Pipeline Behaviour |
|----------|-----------|-------------------|
| Critical | AI explains risk + creates Jira + Slack alert | **Blocks pipeline — human approval required** |
| High | AI explains risk + creates Jira | **Blocks pipeline — human approval required** |
| Medium | AI explains risk + creates Jira | Pipeline continues — human reviews async |
| Low / Info | AI documents finding | Pipeline continues — logged only |

This prevents 15-approval fatigue on a single deployment while ensuring critical findings always gate the pipeline.

---

## Pipeline Architecture
Two-phase design. Build DevOps layer first, then layer in DevSecOps security gates.

---

### Phase 1a — Core DevOps Pipeline (current focus)

| # | Stage | Tools | AI Agent | Blocking? |
|---|-------|-------|----------|-----------|
| 1 | Pre-Commit | Husky + lint-staged, ggshield secret scan | — | Lint blocks; secret scan warns |
| 2 | Raise PR | GitHub Actions | — | — |
| 2a | PR Review | GHAS (CodeQL, Secret Scanning, Dependabot), AI PR Reviewer, Human Review | AI PR Reviewer + AI CodeQL Agent | Critical/High block |
| 3 | PR Merge | GitHub Actions (protected branch) | — | Human approves merge |
| 4 | Checkout | GitHub Actions/checkout, signed commit, supply chain | AI Verification Agent | Critical/High block |
| 5 | Lint | Checkstyle, Flake8, PMD, ESLint | AI Verification Agent | Critical/High block |
| 5a | Secrets Scan | GitGuardian (ggshield) | AI Secrets Agent | Report-only (see note) |
| 6 | SAST | SonarCloud, Bandit | AI SAST Agent | Critical/High block |
| 6a | GHAS | CodeQL, Secret Scanning, Dependabot | AI CodeQL Agent | Critical/High block |
| 7a | Unit Tests | PyTest, JUnit, JaCoCo, coverage.py | AI Verification Agent | Critical/High block |
| 7b | Integration Tests | Testcontainers, REST Assured | AI Verification Agent | Critical/High block |
| 8 | Code Build | pip, npm, Maven, Gradle, artifact build | — | Yes |
| 9 | SCA | Snyk Open Source | AI SCA Agent | Critical/High block |

---

### Phase 1b — IaC, Artifact, Supply Chain & Deploy

| # | Stage | Tools | AI Agent | Blocking? |
|---|-------|-------|----------|-----------|
| 9a | IaC Security Scan | Checkov (Terraform + Kubernetes scan) | AI IaC Security Agent | Critical/High block |
| 10 | Docker Build | Docker (multi-stage, distroless/alpine) | — | Yes |
| 10a | SBOM Generation | Syft, CycloneDX → sbom.json, sbom.spdx.json | AI Supply Chain Agent | Critical/High block |
| 11 | Docker Image Scan | Snyk Container | AI Image Scan Agent | Critical/High block |
| 12 | Docker Image Sign | Cosign, Sigstore (keyless OIDC) | AI Sign Agent | Yes |
| 13 | Docker Image Push | Google Artifact Registry (immutable tags, registry policy) | — | Yes |
| 14 | Helm Lint & Validation | helm, kubeconform | AI Helm Agent | Critical/High block |
| 15 | Security Findings Aggregation | GHAS + SonarCloud + Snyk OSS + Snyk Container + Checkov + Kyverno → security-summary.json | AI Vulnerability Analyzer + AI Exploitability Engine | Critical/High block |

---

### Phase 2 — GitOps, Verification, Security Gates & Runtime

| # | Stage | Tools | AI Agent | Blocking? |
|---|-------|-------|----------|-----------|
| 16 | GitOps Update | Update Helm values / Commit to GitOps repo / ArgoCD Sync | — | Yes |
| 16a | Image Signature Verification | Cosign Verify | AI Sign Agent | **Always blocks** |
| 17 | Kyverno (Admission) | Kyverno admission controller | AI Kyverno Analyzer | Critical/High block |
| 18 | KubeArmor (Runtime) | KubeArmor | AI Runtime Incident Analyzer | Critical/High block |
| 19 | Deploy to Kubernetes | Kubernetes | AI K8s Security Agent | Critical/High block |
| 20 | DAST | OWASP ZAP | AI OWASP Expert Agent | Critical/High block |
| 21 | Monitoring (Continuous) | Prometheus, Grafana, Google Cloud Monitoring, Falco | AI Observability Agent | Alerts only |

---

## Key Flows

### GitOps Flow (ArgoCD)
```
GitHub Actions
      |
      v
Build & Push → Google Artifact Registry
      |
      v
Update Helm Values in GitOps Repo
      |
      v
Commit to GitOps Repo
      |
      v
ArgoCD Detects Drift → Sync
      |
      v
Image Signature Verification (Cosign Verify) ← Stage 16a
      |
      v
Kubernetes (Workloads Running)
```

### PR Review Flow
```
PR Opened
    |
    +--> AI PR Reviewer (code review, security, best practices, bug detection)
    +--> GHAS (CodeQL + Secret Scanning + Dependabot)
    +--> Human Review
    |
    v
Human Approves Merge
```

### Secrets Detection Demo Flow
```
Developer commits AWS key
        |
        v
GitGuardian (ggshield) catches it (Stage 5a)
        |
        v
AI Secrets Agent explains risk + exposure impact
        |
        v
Jira ticket created + Slack alert
        |
        v
Pipeline blocked — human must remediate
```

### AI Remediation Agent Flow
```
Finding (from any tool)
        |
        v
AI Vulnerability Analyzer (aggregates all findings → security-summary.json)
        |
        v
AI Exploitability Engine (cross-correlates tool signals → exploitability score)
        |
        v
AI Remediation Agent
        |
        v
Suggested Fix + Auto-created Pull Request
        |
        v
Human Approval
        |
        v
Merge → Re-trigger Pipeline
```

### Supply Chain Verification Flow
```
Docker Image Built
        |
        v
Cosign Sign (Stage 12) → Signature stored in Sigstore
        |
        v
Image pushed to Artifact Registry
        |
        v
Before ArgoCD Deploy → Cosign Verify (Stage 16a)
        |
        v
Signature valid? → Proceed
Signature invalid? → Block + Alert
```

### Kyverno Policy Failure Flow (AI Kyverno Analyzer)
```
Pod admission request
        |
        v
Kyverno policy check
        |
        v
Policy failed: privileged=true
        |
        v
AI Kyverno Analyzer:
  - Explains risk in plain English
  - Maps to CIS benchmark / PSS standard
  - Suggests remediation (securityContext fix)
  - Creates Jira ticket
        |
        v
Pipeline blocked — human approves fix
```

### Runtime Incident Flow (AI Runtime Incident Analyzer)
```
KubeArmor / Falco alert
        |
        v
AI Runtime Incident Analyzer:
  - Executive summary
  - MITRE ATT&CK mapping
  - Root cause analysis
  - Remediation steps
        |
        v
Slack alert (Critical) + Jira ticket
        |
        v
Human: Triage / Escalate / Respond
```

---

## AI Exploitability Engine — Flagship Feature
Differentiator from GitHub Copilot, Snyk AI, and Sonar AI: cross-tool signal correlation.

```
Inputs:
  Snyk OSS     → Critical CVE found
  GHAS         → Reachable code path confirmed
  Kubernetes   → Service publicly exposed
  Checkov      → No network policy enforced
  KubeArmor    → Anomalous outbound connection detected

AI Exploitability Engine output:
  Exploitability Score: CRITICAL
  Confidence: High
  Reasoning: CVE is reachable, service is internet-facing,
             no network policy, anomalous behaviour observed.
  Conclusion: Immediate remediation required.
  Suggested action: [auto-generated fix PR]
```

This is the differentiator — no individual tool sees the full picture.

---

## AI Agent Registry

| Agent | Active From | Scope |
|-------|-------------|-------|
| AI PR Reviewer | Stage 2a | Code review, security review, best practices, bug detection |
| AI CodeQL Agent | Stage 2a / 6a | GHAS CodeQL findings, secret scanning alerts, Dependabot advisories |
| AI Verification Agent | Stage 4 | Checkout, lint, unit/integration test analysis |
| AI Secrets Agent | Stage 5a | GitGuardian findings — explains exposure risk. Report-only today: the pre-commit hook warns and proceeds, and the CI job is continue-on-error. |
| AI SAST Agent | Stage 6 | Explain vulnerabilities, remediation guidance (Bandit/SonarCloud) |
| AI SCA Agent | Stage 9 | Vulnerability analysis, upgrade recommendations (Snyk OSS) |
| AI IaC Security Agent | Stage 9a | Checkov findings — Terraform + Kubernetes misconfigurations |
| AI Supply Chain Agent | Stage 10a | SBOM analysis, supply chain risk |
| AI Image Scan Agent | Stage 11 | Risk prioritisation, remediation steps (Snyk Container) |
| AI Sign Agent | Stage 12 + 16a | Sign attestation + Cosign verification before deploy |
| AI Helm Agent | Stage 14 | Chart validation, best practices |
| AI Vulnerability Analyzer | Stage 15 | Aggregates ALL findings → security-summary.json |
| AI Exploitability Engine | Stage 15 | Cross-correlates signals → exploitability score + priority |
| AI Remediation Agent | Post-15 | Auto-creates fix PRs from critical/high findings |
| AI Kyverno Analyzer | Stage 17 | Policy violation explanation, CIS/PSS mapping, fix suggestions |
| AI Runtime Incident Analyzer | Stage 18 + 21 | KubeArmor + Falco → executive summary, MITRE mapping, root cause |
| AI K8s Security Agent | Stage 19 | Cluster posture, continuous monitoring, Kubernetes compliance |
| AI OWASP Expert Agent | Stage 20 | Exploit analysis, remediation guidance (OWASP ZAP) |
| AI Observability Agent | Stage 21 | Security alerts, anomaly detection, threat intelligence |

---

## Slack Notification Triggers
- Critical / High vulnerability discovered (any stage)
- Secrets detected (GitGuardian)
- Failed Kyverno policy
- Runtime attack detected (KubeArmor / Falco)
- Image signature verification failed
- Deployment success
- AI Remediation PR auto-created
- DAST critical finding (OWASP ZAP)
- SBOM supply chain anomaly
- AI Exploitability Engine: Critical score

---

## Runtime Security in Kubernetes
```
Container Registry → Kubernetes → Kyverno (Admission Controller) → KubeArmor (Runtime Security)
→ Application Workloads → Prometheus / Grafana / Cloud Monitoring / Falco (Observability)
```

---

## Tech Stack (Full)

| Layer | Tools |
|-------|-------|
| CI/CD | GitHub Actions |
| Pre-commit | Husky, lint-staged, ggshield |
| Secrets scanning | GitGuardian (ggshield) |
| PR review | AI PR Reviewer, GHAS (CodeQL, Secret Scanning, Dependabot) |
| Linting | Flake8, ESLint, Checkstyle, PMD |
| SAST | Bandit, SonarCloud |
| GHAS | CodeQL, Secret Scanning, Dependabot |
| SCA | Snyk Open Source |
| IaC security | Checkov |
| Testing | PyTest, JUnit, JaCoCo, coverage.py, Testcontainers, REST Assured |
| Container build | Docker (multi-stage, distroless/alpine) |
| SBOM | Syft, CycloneDX |
| Image scanning | Snyk Container |
| Image signing | Cosign, Sigstore (keyless OIDC) |
| Image verification | Cosign Verify |
| Registry | Google Artifact Registry (immutable tags) |
| Helm | helm, kubeconform |
| GitOps | ArgoCD *(planned — not yet implemented)* |
| K8s | Kubernetes |
| Admission control | Kyverno |
| Runtime security | KubeArmor |
| DAST | OWASP ZAP |
| Observability | Prometheus, Grafana, Google Cloud Monitoring, Falco |
| Notifications | Slack |
| Ticketing | Jira |
| AI framework | Claude (Anthropic API) |

---

## Cloud
- **Orchestration**: Kubernetes (currently provisioned on Google Cloud —
  GKE, Artifact Registry, Cloud Monitoring; the manifests, Helm charts and
  policies are vendor-neutral)
- **Region/zone**: us-central1 / us-central1-a
- **Auth**: Workload Identity Federation (no long-lived service-account keys)
- **GitOps**: ArgoCD — **not yet implemented**; deploys currently run
  `helm upgrade` directly from `deploy-backend.yaml` / `deploy-frontend.yaml`.

---

## Key Backend Dependencies (CloudCart)

| Package | Purpose | Known Vuln Surface (intentional) |
|---------|---------|----------------------------------|
| Flask + Flask-SQLAlchemy | Web framework + ORM | SQL injection surface |
| Flask-CORS | CORS handling | Misconfigured CORS surface |
| psycopg2-binary | PostgreSQL driver | DB interaction |
| PyJWT | JWT auth | JWT alg:none, weak secrets |
| Werkzeug | WSGI utilities | Debug mode, path traversal |
| Pillow | Image processing | File upload vulns, ImageTragick-style |
| cryptography | Crypto operations | Weak algo usage, key management |
| PyYAML | YAML parsing | yaml.load() deserialization (vs safe_load) |
| requests | HTTP client | SSRF surface |
| prometheus-client | Metrics | Metrics endpoint exposure |
| python-dotenv | Env vars | Secrets management |
| gunicorn | WSGI server | Production server |
| urllib3 | HTTP library | Used by requests internally |

---

## Coding Conventions
- Python: PEP8. **No type hints** — this codebase does not use them (0 of 114
  functions in `scripts/`, 0 of 53 in `backend/`). Do not add them piecemeal;
  a half-annotated tree is worse than an unannotated one because it implies a
  guarantee that only sometimes holds. Adopting them is a deliberate,
  all-at-once decision, not something to slip into an unrelated change.
- Python docstrings: the real convention here, and the one to hold to. Every
  module gets a docstring explaining **why it exists and what failure it
  prevents**, not what it does — `scripts/normalizer_common.py`,
  `backend/routes/identity.py` and `tests/test_workflow_invariants.py` are the
  reference examples. Functions get one when the rationale isn't obvious from
  the name. Prefer one paragraph of real context over a `:param:` block
  restating the signature.
- Comments earn their place by explaining a decision, a constraint, or a bug
  that motivated the code. A comment restating the line below it is noise.
- Flask: use blueprints for route organization, Flask-SQLAlchemy for DB
  interactions — **except** where a planted vulnerability requires otherwise.
  `backend/routes/products.py` builds raw SQL via `db.session.execute(text(...))`
  on purpose; that is the SQL injection the pipeline reports every run, and
  `backend/tests/` asserts it is still there. Do not "fix" it.
- React: functional components only, no class components
- All secrets via environment variables via python-dotenv — never hardcoded
- GitHub Actions: pin all action versions with SHA hashes (supply chain security)
- Docker: multi-stage builds, non-root user, distroless or alpine base images
- Helm: always validate with kubeconform before deploy
- Deployments: `helm upgrade --install` from `deploy-backend.yaml` /
  `deploy-frontend.yaml`. ArgoCD is **not implemented** — no workflow
  references it. The GitOps flow described earlier in this file is target
  design, not current behaviour; write against Helm until that changes.
- Cosign: always verify image signature before ArgoCD deployment (Stage 16a)

---

## Build & Run Commands
```bash
# Backend
cd backend
pip install -r requirements.txt
flask run --debug          # dev
gunicorn main:app          # prod

# Frontend
cd frontend
npm install
npm run dev

# Run tests
cd backend && pytest --cov
cd frontend && npm test

# Lint
cd backend && flake8 .
cd frontend && npm run lint

# Secrets scan
ggshield secret scan repo . --all-secrets

# IaC scan (moved before Docker build)
checkov -d infra/

# SBOM generation
syft . -o cyclonedx-json=sbom.json
syft . -o spdx-json=sbom.spdx.json

# Image sign + verify
cosign sign --key cosign.key <ecr-image>
cosign verify --key cosign.pub <ecr-image>
```

---

## Implementation Status

Not every stage below is built. As of 2026-07-25:

| Implemented | Planned / not built |
|---|---|
| Husky pre-commit, GitGuardian, SonarCloud, CodeQL, Snyk SCA + Container, Checkov, kube-linter, kubeconform, Syft SBOM, Cosign sign + verify, Kyverno, KubeArmor, OWASP ZAP, the AI Release Intelligence engine, and the 507-test suite | ArgoCD/GitOps (deploys run `helm upgrade` directly), Jira ticketing, Slack notifications, the AI Remediation Agent, and Falco |

Stage tables below describe the target design; treat anything in the
"planned" column as aspirational rather than present.

## Current Phase
Phase 1a — Core DevOps pipeline setup. Focus: GitHub Actions workflow skeleton, Husky pre-commit hooks, GitGuardian secret scanning, CodeQL + Dependabot, Flake8 + ESLint + Checkstyle, PyTest + Jest baseline, Snyk Open Source SCA.

---

## Portfolio Context
This is a GitHub showcase project demonstrating AI-augmented DevSecOps. Three flagship features differentiate this from existing tools:

1. **AI Exploitability Engine** — cross-correlates signals from GHAS, SonarCloud, Snyk OSS, Snyk Container, Checkov, and Kyverno to produce a unified exploitability score. No individual tool sees the full picture.
2. **AI Remediation Agent** — auto-creates fix PRs from critical/high findings for human approval.
3. **AI Runtime Incident Analyzer** — maps KubeArmor + Falco alerts to MITRE ATT&CK, produces executive summaries and root cause analysis.

Each phase is a shippable milestone with its own README update and architecture diagram. Prioritize clean, well-documented code over clever abstractions.
