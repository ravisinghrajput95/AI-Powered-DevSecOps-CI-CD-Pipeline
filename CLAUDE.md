# CLAUDE.md — AI-Powered DevSecOps CI/CD Pipeline

## Project Overview
This project builds an AI-powered DevSecOps CI/CD pipeline using GitHub Actions, AWS, and Claude as the AI agent framework. The pipeline runs against **CloudCart** — an intentionally vulnerable 3-tier ecommerce application — to demonstrate real-world AI-assisted security findings, cross-tool exploitability analysis, and automated remediation.

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
  /frontend        # React app (CloudCart UI)
  /backend         # Flask app (CloudCart API)
  /infra           # Kubernetes manifests, Helm charts, Terraform
  /gitops          # GitOps repo for ArgoCD (Helm values, manifests)
  /pipeline        # GitHub Actions workflows, AI agent scripts
  /sbom            # Generated SBOM outputs (sbom.json, sbom.spdx.json)
  /security        # Aggregated security findings (security-summary.json)
  ```

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
| 1 | Pre-Commit | Husky, detect-secrets, IAC scan (optional) | — | Yes |
| 2 | Raise PR | GitHub Actions | — | — |
| 2a | PR Review | GHAS (CodeQL, Secret Scanning, Dependabot), AI PR Reviewer, Human Review | AI PR Reviewer + AI CodeQL Agent | Critical/High block |
| 3 | PR Merge | GitHub Actions (protected branch) | — | Human approves merge |
| 4 | Checkout | GitHub Actions/checkout, signed commit, supply chain | AI Verification Agent | Critical/High block |
| 5 | Lint | Checkstyle, Flake8, PMD, ESLint | AI Verification Agent | Critical/High block |
| 5a | Secrets Scan | Gitleaks, detect-secrets | AI Secrets Agent | **Always blocks** |
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
| 13 | Docker Image Push | AWS ECR (immutable tags, registry policy) | — | Yes |
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
| 19 | Deploy to EKS | AWS EKS, Kubernetes | AI K8s Security Agent | Critical/High block |
| 20 | DAST | OWASP ZAP | AI OWASP Expert Agent | Critical/High block |
| 21 | Monitoring (Continuous) | Prometheus, Grafana, CloudWatch, Falco | AI Observability Agent | Alerts only |

---

## Key Flows

### GitOps Flow (ArgoCD)
```
GitHub Actions
      |
      v
Build & Push → AWS ECR
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
AWS EKS (Workloads Running)
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
Gitleaks + detect-secrets catch it (Stage 5a)
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
Image pushed to ECR
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
| AI Secrets Agent | Stage 5a | Gitleaks + detect-secrets findings — explains exposure risk, always blocks |
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
| AI K8s Security Agent | Stage 19 | Cluster posture, continuous monitoring, EKS compliance |
| AI OWASP Expert Agent | Stage 20 | Exploit analysis, remediation guidance (OWASP ZAP) |
| AI Observability Agent | Stage 21 | Security alerts, anomaly detection, threat intelligence |

---

## Slack Notification Triggers
- Critical / High vulnerability discovered (any stage)
- Secrets detected (Gitleaks / GHAS Secret Scanning)
- Failed Kyverno policy
- Runtime attack detected (KubeArmor / Falco)
- Image signature verification failed
- Deployment success
- AI Remediation PR auto-created
- DAST critical finding (OWASP ZAP)
- SBOM supply chain anomaly
- AI Exploitability Engine: Critical score

---

## Runtime Security in AWS EKS
```
Amazon ECR → Amazon EKS → Kyverno (Admission Controller) → KubeArmor (Runtime Security)
→ Application Workloads → Prometheus / Grafana / CloudWatch / Falco (Observability)
```

---

## Tech Stack (Full)

| Layer | Tools |
|-------|-------|
| CI/CD | GitHub Actions |
| Pre-commit | Husky, detect-secrets |
| Secrets scanning | Gitleaks, detect-secrets, GHAS Secret Scanning |
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
| Registry | AWS ECR (immutable tags) |
| Helm | helm, kubeconform |
| GitOps | ArgoCD |
| K8s | AWS EKS |
| Admission control | Kyverno |
| Runtime security | KubeArmor |
| DAST | OWASP ZAP |
| Observability | Prometheus, Grafana, CloudWatch, Falco |
| Notifications | Slack |
| Ticketing | Jira |
| AI framework | Claude (Anthropic API) |

---

## Cloud
- **Primary**: AWS (EKS, ECR, CloudWatch)
- **GitOps**: ArgoCD on EKS
- **Region**: to be confirmed

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
- Python: PEP8, type hints on all functions, docstrings on public methods
- Flask: use blueprints for route organization, Flask-SQLAlchemy for all DB interactions
- React: functional components only, no class components
- All secrets via environment variables via python-dotenv — never hardcoded
- GitHub Actions: pin all action versions with SHA hashes (supply chain security)
- Docker: multi-stage builds, non-root user, distroless or alpine base images
- Helm: always validate with kubeconform before deploy
- ArgoCD: all deployments via GitOps — no direct kubectl apply in pipeline
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
gitleaks detect --source . --verbose
detect-secrets scan > .secrets.baseline

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

## Current Phase
Phase 1a — Core DevOps pipeline setup. Focus: GitHub Actions workflow skeleton, Husky pre-commit hooks, Gitleaks + detect-secrets setup, GHAS (CodeQL + Secret Scanning + Dependabot), Flake8 + ESLint + Checkstyle, PyTest + Jest baseline, Snyk Open Source SCA.

---

## Portfolio Context
This is a GitHub showcase project demonstrating AI-augmented DevSecOps. Three flagship features differentiate this from existing tools:

1. **AI Exploitability Engine** — cross-correlates signals from GHAS, SonarCloud, Snyk OSS, Snyk Container, Checkov, and Kyverno to produce a unified exploitability score. No individual tool sees the full picture.
2. **AI Remediation Agent** — auto-creates fix PRs from critical/high findings for human approval.
3. **AI Runtime Incident Analyzer** — maps KubeArmor + Falco alerts to MITRE ATT&CK, produces executive summaries and root cause analysis.

Each phase is a shippable milestone with its own README update and architecture diagram. Prioritize clean, well-documented code over clever abstractions.
