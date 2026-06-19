# Cloudcart Helm Charts

## Structure
```
helm/
├── cloudcart/                    # Umbrella chart
│   ├── Chart.yaml
│   ├── values.yaml               # Default values
│   ├── values-prod.yaml          # Production overrides
│   └── charts/
│       ├── frontend/             # React frontend
│       ├── backend/              # Flask backend
│       └── postgresql/           # PostgreSQL StatefulSet
│           └── files/
│               └── init.sql      # ← Copy your database/init.sql here
└── monitoring/
    ├── values.yaml               # kube-prometheus-stack config
    └── grafana-dashboard-configmap.yaml
```

## Prerequisites
```bash
# 1. Authenticate to GKE
gcloud container clusters get-credentials <CLUSTER_NAME> --zone <ZONE>

# 2. Add Helm repos
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
```

## Step 1: Copy your init.sql
```bash
cp database/init.sql helm/cloudcart/charts/postgresql/files/init.sql
```

## Step 2: Deploy Cloudcart
```bash
# Create namespace
kubectl apply -f helm/cloudcart/templates/namespace.yaml

# Install umbrella chart
helm upgrade --install cloudcart ./helm/cloudcart \
  --namespace cloudcart \
  --set global.projectId=YOUR_GCP_PROJECT_ID \
  --set frontend.image.repository=gcr.io/YOUR_PROJECT/cloudcart-frontend \
  --set frontend.image.tag=latest \
  --set backend.image.repository=gcr.io/YOUR_PROJECT/cloudcart-backend \
  --set backend.image.tag=latest \
  --set postgresql.password=CloudCartDB_Pass123! \
  --set backend.secretKey=cloudcart-super-secret-key-12345 \
  --wait
```

## Step 3: Deploy Monitoring
```bash
# Apply Grafana dashboard configmap
kubectl apply -f helm/monitoring/grafana-dashboard-configmap.yaml

# Install kube-prometheus-stack
helm upgrade --install monitoring prometheus-community/kube-prometheus-stack \
  -f helm/monitoring/values.yaml \
  --namespace monitoring \
  --create-namespace \
  --wait
```

## Step 4: Get Public IPs
```bash
# Frontend IP
kubectl get svc cloudcart-frontend -n cloudcart

# Grafana IP
kubectl get svc monitoring-grafana -n monitoring
```

## Verify Everything is Running
```bash
kubectl get all -n cloudcart
kubectl get all -n monitoring
```

## Uninstall
```bash
helm uninstall cloudcart -n cloudcart
helm uninstall monitoring -n monitoring
```
