# cloudcart-bootstrap

Cluster prerequisites for CloudCart. **Install once per cluster, before
`helm/postgresql` and `helm/cloudcart`.**

```bash
helm dependency update helm/bootstrap
helm upgrade --install cloudcart-bootstrap helm/bootstrap \
  --namespace cloudcart-system --create-namespace --wait --timeout 15m
```

## Why this exists

Every item here was installed by hand during the 2026-07-25 cluster
rebuild. None of it lived in the repo, so a from-scratch cluster could not
reproduce the working environment — and each omission surfaced as what
looked like a bug in this repository rather than a missing prerequisite:

| Missing | Symptom |
|---|---|
| Prometheus Operator CRDs | `cloudcart` release fails: `no matches for kind "ServiceMonitor"` |
| Kyverno | `runtime-security-scan` fails at `kubectl get policyreport` |
| KubeArmor operator | `no matches for kind "KubeArmorPolicy"` |
| `KubeArmorConfig` CR | Operator installs but never deploys the DaemonSet or registers the policy CRD |
| `kubearmor-visibility` namespace annotation | Policies load and the DaemonSet enforces, but **zero** `MatchedPolicy` alerts are ever produced |

That last one is the subtlest: everything looks healthy — telemetry flows,
policies are `Detected`, the DaemonSet runs with BPF-LSM — but every event
carries `PolicyName: null` and `Enforcer: null`, so the runtime domain is
silently empty rather than visibly broken.

## Ordering

1. `helm/bootstrap` — this chart (CRDs, controllers, annotated namespace)
2. `helm/postgresql` — database, schema, and seed ConfigMaps
3. `helm/cloudcart` — the application

Step 2 before step 3 is not optional: `cloudcart-db-init` mounts the
`db-schema-sql` ConfigMap that the postgresql chart creates, so installing
the app into a namespace without it hangs the post-install hook until Helm
times out.

## Node sizing

`kube-prometheus-stack` is the largest consumer here. On 2026-07-25 a
3-node `e2-medium` pool reached 90–98% allocatable CPU with the stack plus
the app, and Kyverno's admission and cleanup controllers stayed `Pending`
with `0/3 nodes are available: 3 Insufficient cpu`. Either provision ≥5
nodes of that size, or trim the requests in `values.yaml`.

Set `kube-prometheus-stack.enabled=false` if you only need the security
controllers — but then also leave `serviceMonitor.enabled=false` in
`helm/cloudcart`, since the CRDs it needs come from here.
