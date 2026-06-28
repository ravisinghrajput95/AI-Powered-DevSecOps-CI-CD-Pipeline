# CloudCart - Cloud-Native E-Commerce

> **WARNING:** This application is **intentionally insecure**. It exists solely for AI-augmented DevSecOps platform POC, security tool evaluation, and pipeline demonstration. **Never deploy to production or expose to the public internet.**

CloudCart is a fully functional cloud-native e-commerce application with realistic vulnerabilities and misconfigurations designed to generate rich findings across the DevSecOps toolchain.

## Architecture

```text
+-------------+     +-------------+     +--------------+
| React       | --> | Flask API   | --> | PostgreSQL   |
| Vite SPA    |     | SQLAlchemy  |     | Database     |
+-------------+     +------+------+     +--------------+
                           |
                    +------v-------+
                    | Prometheus   |
                    | Grafana      |
                    +--------------+
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 18, Vite, Axios |
| Backend | Flask, SQLAlchemy, Gunicorn |
| Database | PostgreSQL 13 |
| Containers | Docker, Docker Compose |
| Orchestration | Kubernetes, Helm |
| Infrastructure | Terraform (GKE) |
| Observability | Prometheus, Grafana |
| CI/CD | GitHub Actions |
| Security | Kyverno, KubeArmor, Cosign, Checkov, Snyk, GitGuardian, Kubelinter, Kubeconform, Syft, SonarCloud, CodeQL, Dependabot, GHAS, SBOM, ZAP |
| **AI Release Intelligence** | **Claude (forced tool-use) — see [AI Release Intelligence Platform](#ai-release-intelligence-platform) below** |

## Business Features

- User registration and login
- Product catalog with search
- Shopping cart and checkout
- Product reviews
- Order management
- User profile and file upload
- Admin dashboard

## Intentional Vulnerabilities

### Application (OWASP Top 10)

| Vulnerability | Location |
|---------------|----------|
| SQL Injection | `backend/routes/products.py` - `/api/products/search` |
| XSS (Stored) | `frontend/src/components/ReviewList.jsx` - `dangerouslySetInnerHTML` |
| SSRF | `backend/routes/vulnerable.py` - `/api/vuln/fetch`, `/api/vuln/proxy` |
| Command Injection | `backend/routes/admin.py` - `/api/admin/exec` |
| Path Traversal | `backend/routes/vulnerable.py` - `/api/vuln/file` |
| Insecure File Upload | `backend/routes/vulnerable.py` - `/api/vuln/upload` |
| Hardcoded Secrets | `backend/config.py`, `secrets/credentials.json` |
| Sensitive Info Exposure | `/api/config`, `/api/admin/env`, `/api/vuln/debug` |
| Broken Access Control | Admin routes, profile update, cart/orders IDOR |
| Missing Authorization | Product create, order status update, review delete |
| Debug Mode Enabled | `FLASK_DEBUG=true` throughout |
| Weak Session Management | Insecure cookies, long-lived JWT, localStorage tokens |

### Dependency Vulnerabilities

- **Python (Docker / Snyk):** see `backend/requirements-vulnerable.txt` - Flask 2.0.1, Pillow 8.3.2, PyJWT 1.7.1, etc.
- **Python (local dev):** `backend/requirements.txt` - installable on Python 3.11 through 3.13.
- **npm:** axios 0.21.1, lodash 4.17.15, moment 2.29.1 (`frontend/package.json`).

### Container Security

- Root containers (no `USER` directive)
- Missing `HEALTHCHECK`
- Secrets in `ENV` variables
- Outdated base images (`python:3.7-slim`, `node:14-alpine`, `nginx:latest`)
- Mutable `:latest` image tags

### Kubernetes Misconfigurations

- Privileged containers, `hostNetwork: true`
- `hostPath` mounts, including `/var/run/docker.sock`
- `cluster-admin` RBAC binding
- Default service account with excessive permissions
- Missing resource limits
- Public `LoadBalancer` service
- No NetworkPolicies
- Secrets in plain-text manifests

### Terraform Misconfigurations

- Firewall rules open to `0.0.0.0/0`
- Overly permissive IAM (`roles/owner`, `roles/storage.admin`)
- Public GCS bucket
- Disabled logging/monitoring
- Legacy ABAC enabled
- Private cluster disabled

## Tool Coverage Matrix

| Tool | What It Finds |
|------|---------------|
| GitHub Advanced Security (CodeQL) | SQLi, command injection, SSRF patterns |
| GitGuardian | Hardcoded secrets in code, configs, workflows |
| SonarCloud | Code smells, security hotspots, duplication |
| Snyk Open Source | Vulnerable Python/npm dependencies |
| Snyk Container | CVEs in Docker base images |
| Syft / CycloneDX | SBOM generation |
| Checkov | Terraform, Kubernetes, Helm misconfigs |
| Kyverno | Privileged pods, missing limits, hostPath |
| KubeArmor | Runtime process/file violations |
| Cosign | Image signing and verification |
| ZAP | DAST | 
| Prometheus / Grafana | Application metrics dashboards |
| **AI Release Intelligence Agent** | **Cross-domain correlation, prioritized risk reasoning, release readiness recommendation — see below** |

## Project Structure

```text
Cloudcart/
|-- frontend/                 # React + Vite SPA
|   |-- public/images/         # SVG and product catalog image assets
|   `-- src/
|-- backend/                  # Flask REST API
|-- database/                 # PostgreSQL init SQL
|-- helm/
|   |-- cloudcart/            # Application Helm chart
|   |-- postgresql/           # Database Helm chart
|   `-- monitoring/           # Prometheus/Grafana Helm chart
|-- terraform/                # GKE infrastructure
|-- monitoring/               # Prometheus and Grafana configs
|-- policies/
|   |-- kyverno/              # Kyverno cluster policies (pod-security, supply-chain)
|   `-- kubearmor/            # KubeArmor runtime policies
|-- .github/workflows/        # CI/CD + AI Release Intelligence pipelines
|-- scripts/                  # Normalizers, ReleaseContext builders, AI agent, renderers
|-- tests/                    # 507 automated tests + golden regression dataset
|-- docker-compose.yml
|-- README.md
```
## Quick Start (Docker Compose)

### Prerequisites

- Python 3.11+ (3.13 supported)
- Node.js 18+
- Docker (recommended for PostgreSQL)

### 1. Start PostgreSQL

```bash
docker compose up -d postgres
```

### 2. Backend (terminal 1)

**Windows (PowerShell):**

```powershell
cd backend
.\run-backend.ps1
```

**macOS / Linux:**

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=postgresql://cloudcart:CloudCartDB_Pass123!@localhost:5432/cloudcart
python app.py
```

API health check: http://localhost:5000/health

> Use `requirements-vulnerable.txt` only inside Docker images. Local installs use `requirements.txt`.

### 3. Frontend (terminal 2)

```bash
cd frontend
npm install
npm run dev
```

App: http://localhost:3000

> **ECONNREFUSED on `/api`?** The backend must be running on port 5000 before using the UI.

### Demo Login

- **admin** / **admin123**
- Or register at http://localhost:3000/register

## Product Images

Product catalog images are served from:

```text
frontend/public/images/products/
```

The seed data and product API return image paths such as `/images/products/headphones.jpg`. If catalog images look stale in development, restart the frontend server or hard refresh the browser cache.

## Kubernetes Deployment

### Prerequisites

- `kubectl` configured
- Container images built and available to the target cluster

### Build images

```bash
docker build -t cloudcart-backend:latest ./backend
docker build -t cloudcart-frontend:latest ./frontend
```

### Load into kind/minikube if local
kind load docker-image cloudcart-backend:latest
kind load docker-image cloudcart-frontend:latest

### Deploy with Helm

```bash
helm upgrade --install cloudcart ./helm/cloudcart \
  --namespace cloudcart \
  --create-namespace \
  --wait
```

### Apply Security Policies

```bash
# Kyverno policies (audit mode)
kubectl apply -f policies/kyverno/

# KubeArmor policies
kubectl apply -f policies/kubearmor/
```

## GKE Deployment (Terraform)

### Prerequisites

- Google Cloud SDK (`gcloud`)
- Terraform >= 1.0
- GCP project with billing enabled

### Steps

```bash
# Authenticate
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

# Configure Terraform
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your project_id

terraform init
terraform plan
terraform apply

# Get cluster credentials
gcloud container clusters get-credentials cloudcart-gke \
  --zone us-central1-a --project YOUR_PROJECT_ID

# Build and push images to GCR/Artifact Registry
docker tag cloudcart-backend:latest gcr.io/YOUR_PROJECT_ID/cloudcart-backend:latest
docker push gcr.io/YOUR_PROJECT_ID/cloudcart-backend:latest

# Deploy
helm upgrade --install cloudcart ../helm/cloudcart \
  --namespace cloudcart \
  --create-namespace \
  --set image.backend.repository=gcr.io/YOUR_PROJECT_ID/cloudcart-backend \
  --set image.frontend.repository=gcr.io/YOUR_PROJECT_ID/cloudcart-frontend
```

## CI/CD Pipeline

The pipeline is split across several focused workflows, not one monolithic file — each scanner's workflow records its own real success/failure status, which the AI Release Intelligence pipeline (below) reads rather than assumes.

| Workflow | Triggers on | Produces |
|---|---|---|
| `backend-ci.yaml` / `frontend-ci.yaml` | `backend/**` / `frontend/**`, plus Helm chart changes | Build, unit tests |
| `app-security-scan-backend.yaml` / `-frontend.yaml` | `backend/**` / `frontend/**` | CodeQL, SonarCloud, GitGuardian, Snyk SCA findings + `scan_status_*.json` |
| `infra-security-scan.yaml` | `helm/**`, `terraform/**` | Checkov, kube-linter, kubeconform findings |
| `infra-readiness.yml` | manual / scheduled | Merges infra findings into `infra_context.json`, with latest-successful-run fallback if no exact commit match exists |
| `runtime-security-scan.yaml` | deploy / manual | Kyverno, KubeArmor, ZAP findings against the live cluster |
| `release-readiness.yaml` | manual / release | Pulls the above into `final_release_context.json`, runs the AI Release Intelligence Agent, renders the report |

### Required Secrets

| Secret | Purpose |
|--------|---------|
| `SNYK_TOKEN` | Snyk vulnerability scanning |
| `SONAR_TOKEN` | SonarCloud analysis |
| `GITGUARDIAN_API_KEY` | GitGuardian secret scanning |
| `ANTHROPIC_API_KEY` | AI Release Intelligence Agent |

Scans are designed to produce findings even when secrets are not set; several workflow steps use `continue-on-error` where appropriate.

## AI Release Intelligence Platform

Every scanner above produces its own raw, tool-specific output. This platform turns that into one structured, evidence-grounded release decision — not a dashboard aggregating numbers, an actual reasoned recommendation with citations back to real findings.

**Full design, schema reference, domain model, and workflow orchestration diagram: [ARCHITECTURE.md](ARCHITECTURE.md)**

Three strictly separated layers — security tools own facts, Python owns deterministic computation, AI owns reasoning only, humans own the actual deployment decision:

```mermaid
flowchart TD
    subgraph Tools["Raw security tool output"]
        T1[Checkov]
        T2["kube-linter / kubeconform"]
        T3[CodeQL]
        T4[SonarCloud]
        T5[GitGuardian]
        T6[Snyk SCA]
        T7[Kyverno]
        T8[KubeArmor]
        T9[ZAP]
    end

    subgraph Normalize["scripts/normalize_*.py"]
        N["One canonical Finding shape<br/>(severity, category, type, confidence, finding_id)"]
    end
    T1 --> N
    T2 --> N
    T3 --> N
    T4 --> N
    T5 --> N
    T6 --> N
    T7 --> N
    T8 --> N
    T9 --> N

    N --> B1["build_release_context.py<br/>app + runtime findings"]
    N --> B2["build_infra_context.py<br/>infra + terraform findings"]

    B1 --> C["compose_release_context.py<br/>merge · assign_domain · compute statistics"]
    B2 --> C

    C --> RC[("final_release_context.json<br/>ReleaseContext v1.0 — frozen")]

    RC --> AI["AI Release Intelligence Agent<br/>run_security_analysis.py<br/>Claude, forced tool-use, schema-validated"]
    AI --> ER[("executive_report.json<br/>ExecutiveReport v1.0 — frozen")]

    ER --> R1["render_report.py → Markdown"]
    ER --> R2["render_html_report.py → HTML"]
    RC -. resolves finding_id citations .-> R1
    RC -. resolves finding_id citations .-> R2
```

### What's actually validated, with real data — not assumed

| Domain | Status |
|---|---|
| `infrastructure_security` | Validated across many real CI runs |
| `runtime_security` | Validated across many real CI runs |
| `application_security` | **Validated with real data** — 119 real findings from CodeQL/SonarCloud/GitGuardian/Snyk SCA in one real run, zero invalid citations, correct cross-domain correlation integrity |
| `container_security` | **Real findings confirmed flowing through** (8 real CVEs in one real run) — narrower than `application_security`'s validation: confirms the data path, not yet AI-reasoning/citation correctness for this domain specifically |

### Test suite

507 automated tests (`tests/`) — schema validation, evidence-citation integrity, cross-domain correlation integrity, renderer correctness, and a golden regression dataset covering 8 representative scenarios. Full detail in [ARCHITECTURE.md](ARCHITECTURE.md#test-suite).

```bash
pip install -r tests/requirements.txt
python3 -m pytest
```

Known gaps and the full domain-assignment/schema reference: see [ARCHITECTURE.md](ARCHITECTURE.md#known-gaps).

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register user |
| POST | `/api/auth/login` | Login |
| GET | `/api/products/` | List products |
| GET | `/api/products/search?q=` | Search (SQLi) |
| GET/POST | `/api/cart/` | Shopping cart |
| POST | `/api/orders/checkout` | Place order |
| POST | `/api/reviews/` | Create review (XSS) |
| GET | `/api/admin/stats` | Admin stats (no auth) |
| POST | `/api/admin/exec` | Command execution |
| POST | `/api/vuln/fetch` | SSRF |
| POST | `/api/vuln/upload` | File upload |
| GET | `/metrics` | Prometheus metrics |

## AI Platform Integration

This codebase generates findings consumed by the **AI Release Intelligence Platform** (see [above](#ai-release-intelligence-platform)) — a single AI agent that reasons across CodeQL/Snyk/SonarCloud/GitGuardian (application), Checkov/kube-linter (infrastructure), and Kyverno/KubeArmor/ZAP (runtime) findings together, correlates them across domains, and produces a cited, schema-validated release readiness recommendation. This replaces what an earlier draft of this README described as a list of separate, hypothetical future tools (a vulnerability analyzer, a remediation expert, a PR reviewer, etc.) — those ideas converged into the one real, validated system documented above, not into the multiple speculative tools previously listed here.

## Security Testing Examples

```bash
# SQL Injection
curl "http://localhost:5000/api/products/search?q=' OR '1'='1"

# SSRF
curl -X POST http://localhost:5000/api/vuln/fetch \
  -H "Content-Type: application/json" \
  -d '{"url": "http://169.254.169.254/latest/meta-data/"}'

# Path Traversal
curl "http://localhost:5000/api/vuln/file?path=etc/passwd"

# Exposed Config
curl http://localhost:5000/api/config
```

## Pushing to GitHub

This repository intentionally contains vulnerable code, weak configuration, and sample secrets for training. Prefer a private repository unless public exposure is part of your training plan.

```bash
git add .
git commit -m "Initial commit: CloudCart DevSecOps training application"
git branch -M main
git remote add origin https://github.com/YOUR_ORG/cloudcart.git
git push -u origin main
```

Configure GitHub Actions secrets (`SNYK_TOKEN`, `SONAR_TOKEN`, etc.) for full pipeline runs. Scans are designed to produce findings even when secrets are not set; several workflow steps use `continue-on-error` where appropriate.

## License

MIT License - see [LICENSE](LICENSE). This project is for **educational and security training only**. Use responsibly in isolated environments.
