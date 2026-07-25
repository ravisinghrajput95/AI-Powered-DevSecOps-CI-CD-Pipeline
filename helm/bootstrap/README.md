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
| `kubearmor-visibility` namespace annotation | Required by KubeArmor for per-namespace visibility. **Not sufficient on its own** — see the known issue below. |

## Known issue: KubeArmor produces no `MatchedPolicy` alerts

**Unresolved as of 2026-07-25.** KubeArmor installs, enforces, and reports
telemetry correctly, but no policy ever matches, so
`normalized-kubearmor.json` is always `[]` and the runtime domain silently
loses its most important signal. It looks healthy from every angle, which
is why this is written down rather than left to be rediscovered.

What was verified working:

- `Supported LSMs: ... apparmor,bpf,ima` → `Initialized BPF-LSM Enforcer`
  → `Initialized KubeArmor Enforcer` → `Starting TraceEvents from BPF LSM
  Enforcer`
- All 8 policies registered (`kubectl get kubearmorpolicy -n cloudcart`)
  and logged as `Detected a Security Policy`
- The target pod is `Detected`, annotated `kubearmor-policy: enabled` and
  `kubearmor-visibility: process,file,network,capabilities`, and scheduled
  on the same node as the KubeArmor DaemonSet pod that loaded the policies
- Pod labels match the policy selector (`app: cloudcart-backend`)
- `/bin/sh` is a symlink to `dash`, and `matchPaths` contains both
- Telemetry flows: 1,470 events in ~30s, correctly attributed to the
  `backend` container, including the exact triggering process
  (`Resource: "/bin/sh -c id"`)

Hypotheses tested and eliminated:

| Hypothesis | Result |
| --- | --- |
| BPF-LSM unavailable on GKE COS | Disproven — enforcer initialises, DaemonSet is `kubearmor-bpf-containerd` |
| Namespace missing `kubearmor-visibility` | Applied; pods restarted after; still zero alerts |
| Pod started before KubeArmor | Disproven — a pod created hours later behaves identically |
| Policy selector / label mismatch | Disproven — labels match exactly |
| `/bin/sh` symlink not covered by `matchPaths` | Disproven — `/bin/dash` is listed too |
| `kubectl exec` not traced (enters via the runtime, not container init) | Disproven — a shell spawned by the app's own `subprocess(shell=True)` is also unmatched |

Every event arrives as `Type: ContainerLog` with `PolicyName: null`; no
`MatchedPolicy` event is produced under `--logFilter=policy` or
`--logFilter=all`. Note `Enforcer: null` on a ContainerLog is expected —
that field is only populated on policy alerts — so it is a symptom, not
the cause.

Next step is upstream: this looks like a KubeArmor v1.5.7 / GKE-COS
interaction rather than a configuration error in this repo.

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
