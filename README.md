# CloudCart - Cloud-Native E-Commerce (DevSecOps Training)

> **WARNING:** This application is **intentionally insecure**. It exists solely for AI-augmented DevSecOps platform training, security tool evaluation, and pipeline demonstration. **Never deploy to production or expose to the public internet.**

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
| CI/CD | GitHub Actions, ArgoCD |
| Security | Kyverno, KubeArmor, Cosign, Checkov, Snyk, Gitleaks, SonarQube, CodeQL |

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
| Gitleaks | Hardcoded secrets in code, configs, workflows |
| SonarQube | Code smells, security hotspots, duplication |
| Snyk Open Source | Vulnerable Python/npm dependencies |
| Snyk Container | CVEs in Docker base images |
| Syft / CycloneDX | SBOM generation |
| Checkov | Terraform, Kubernetes, Helm misconfigs |
| Kyverno | Privileged pods, missing limits, hostPath |
| KubeArmor | Runtime process/file violations |
| ArgoCD | GitOps drift, deployment sync |
| Cosign | Image signing and verification |
| Prometheus / Grafana | Application metrics dashboards |
| Slack / Jira | Pipeline notifications and ticket creation |

## Project Structure

```text
Cloudcart/
|-- frontend/                 # React + Vite SPA
|   |-- public/images/         # SVG and product catalog image assets
|   `-- src/
|-- backend/                  # Flask REST API
|-- database/                 # PostgreSQL init SQL
|-- k8s/                      # Kubernetes manifests (Kustomize)
|-- helm/cloudcart/           # Helm chart
|-- terraform/                # GKE infrastructure
|-- monitoring/               # Prometheus and Grafana configs
|-- security/
|   |-- kyverno/              # Kyverno cluster policies
|   `-- kubearmor/            # KubeArmor runtime policies
|-- argocd/                   # ArgoCD Application manifest
|-- .github/workflows/        # CI/CD pipelines
|-- secrets/                  # Sample credentials (Gitleaks targets)
|-- scripts/                  # Utility scripts
|-- docker-compose.yml
|-- Makefile
`-- README.md
```

## Quick Start (Docker Compose)

### Prerequisites

- Docker and Docker Compose
- 4 GB RAM minimum

### Run

```bash
# Clone and start
git clone <repo-url> cloudcart
cd cloudcart
make build
make up

# Seed products if DB init did not run
make seed
```

### Access

| Service | URL | Credentials |
|---------|-----|-------------|
| Frontend | http://localhost:3000 | n/a |
| API | http://localhost:5000 | n/a |
| Prometheus | http://localhost:9090 | n/a |
| Grafana | http://localhost:3001 | admin / admin |

### Demo Login

- **Admin:** `admin` / `admin123`
- Or register a new account at `/register`

## Local Development (without full Docker)

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

### Deploy with kubectl

```bash
# Build images
docker build -t cloudcart-backend:latest ./backend
docker build -t cloudcart-frontend:latest ./frontend

# Load into kind/minikube if local
kind load docker-image cloudcart-backend:latest
kind load docker-image cloudcart-frontend:latest

# Deploy
kubectl apply -k k8s/

# Verify
kubectl get pods -n cloudcart
kubectl get svc -n cloudcart
```

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
kubectl apply -f security/kyverno/

# KubeArmor policies
kubectl apply -f security/kubearmor/
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

The GitHub Actions workflow (`.github/workflows/ci-cd.yml`) runs:

1. **Gitleaks** - secret scanning
2. **SonarQube** - static analysis
3. **CodeQL** - semantic security analysis
4. **Snyk** - dependency and container scanning
5. **Syft** - SBOM generation (CycloneDX)
6. **Checkov** - IaC policy scanning
7. **Cosign** - container image signing
8. **Helm deploy** - staging deployment
9. **Kyverno** - policy validation
10. **Slack / Jira** - notifications

### Required Secrets

| Secret | Purpose |
|--------|---------|
| `SNYK_TOKEN` | Snyk vulnerability scanning |
| `SONAR_TOKEN` | SonarQube analysis |
| `SLACK_WEBHOOK_URL` | Pipeline notifications |
| `JIRA_URL` | Jira ticket creation |
| `JIRA_AUTH` | Jira API authentication |

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

This codebase generates findings suitable for:

- **AI Vulnerability Analyzer** - maps CodeQL/Snyk/Sonar findings to CWE/OWASP
- **AI Vulnerability Remediation Expert** - suggests fixes for each vulnerability class
- **AI PR Reviewer** - reviews pull requests against security policies
- **AI Kubernetes Manifest Reviewer** - analyzes K8s/Helm misconfigurations
- **AI Terraform Reviewer** - evaluates IaC security posture
- **AI Kyverno Findings Analyzer** - interprets policy violation reports
- **AI KubeArmor Incident Analyzer** - correlates runtime security events

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
