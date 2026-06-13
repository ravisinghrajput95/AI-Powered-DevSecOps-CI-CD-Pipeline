# Monitoring

| File | Purpose |
|------|---------|
| `prometheus/prometheus.yml` | Docker Compose / local Prometheus scrape config |
| `prometheus/prometheus-k8s.yml` | Kubernetes pod discovery (GKE/kind) |
| `grafana/provisioning/datasources/datasource.yaml` | Grafana Prometheus datasource (`uid: prometheus`) |
| `grafana/provisioning/dashboards/dashboard.yml` | Dashboard file provider |
| `grafana/dashboards/cloudcart-overview.json` | CloudCart metrics dashboard |

**Note:** Do not name Grafana datasource files `prometheus.yml` — IDEs apply the Prometheus server schema and show false YAML errors.
