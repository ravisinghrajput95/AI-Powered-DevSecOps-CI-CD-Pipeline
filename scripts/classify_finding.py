#!/usr/bin/env python3
"""
Shared classification logic used by all three normalizers to populate
category, confidence, and recommendation fields.

IMPORTANT: This is rule-based pattern matching against rule_id/message
text, not provided natively by any of the 3 tools (CodeQL, SonarCloud,
GitGuardian). Coverage is built against rule_ids actually observed in
this project's real scan output as of 2026-06-20. New rule_ids from
future scans that don't match any pattern below will fall through to
the "uncategorized" / "unknown" fallback — extend the tables as new
rule_ids appear rather than assuming silence means "no issues".
"""
import re
import sys

# ─────────────────────────────────────────────────────────────────
# CATEGORY: ordered list of (pattern, category) — first match wins.
# Patterns match against a combined "<rule_id> <message>" string,
# case-insensitive.
# ─────────────────────────────────────────────────────────────────
CATEGORY_RULES = [
    # Network exposure — checked BEFORE secret-exposure so a hardcoded IP
    # (e.g. AWS metadata endpoint 169.254.169.254) doesn't get caught by
    # the broader "hard-coded" pattern below.
    (r"binding the application to all network interfaces|hardcoded ip address|0\.0\.0\.0|bind.*all interfaces|listen.*0\.0\.0\.0", "network-exposure"),

    # Secrets / credentials — covers all 3 tools' own secret detectors
    (r"secret|password|api[_-]?key|credential|hard-?coded credential|stripe|username password|compromised|hard-?coded secret|access[_-]?key|private[_-]?key|auth[_-]?token|bearer token", "secret-exposure"),

    # Known CVEs in OS packages / language dependencies, as reported by
    # container/SCA scanners (e.g. Snyk's rule_ids look like
    # "SNYK-DEBIAN12-OPENSSL-1234567" or "SNYK-JS-LODASH-1018905"). Distinct
    # from the source-code-pattern categories below: these are pre-existing
    # known vulnerabilities in third-party code, not a pattern in code this
    # project wrote, so remediation is "upgrade the package", not "fix the code".
    (r"^snyk-|\bcve-\d{4}-\d+\b|vulnerable (?:version|package|dependency|module)|known vulnerabilit", "vulnerable-dependency"),

    # License compliance issues (Snyk Open Source's license scanning). This
    # category has no clean home in the security|quality|performance|
    # accessibility type vocabulary — it's a legal/compliance risk, not any
    # of those. Mapped to "security" below as the closest fit (same
    # fail-safe reasoning as everywhere else: better to over-include than
    # bury it), but flagging the taxonomy gap rather than pretending it
    # fits cleanly.
    (r"license issue|license violation|license polic|licensing issue", "license-risk"),

    # Injection family
    (r"sql-injection|sql query.*user-provided|sql.*injection|injectable sql", "injection"),
    (r"construct the os command|command-line-injection|command line.*user-provided|os command.*user|shell.*injection|command injection", "injection"),
    (r"path-injection|construct the path from user-controlled|path depends on a.*user-provided|path traversal|directory traversal|zip.?slip", "path-traversal"),
    (r"full-ssrf|construct the url from user-controlled|url of this request depends on|server-side request forgery|\bssrf\b", "ssrf"),

    # Client-side request handling (frontend/browser fetch construction) —
    # kept distinct from the backend "ssrf" category above: same root cause
    # (untrusted data shapes an outbound request URL) but the browser issues
    # the request, not the server, so the blast radius and remediation
    # (client-side allowlisting) differ from server-side SSRF.
    (r"construct the url.?s path from user-controlled|tainted data is validated before being used to construct a client-side request url", "client-side-request-forgery"),

    (r"reflective-xss|reflect unsanitized user-controlled|cross-site scripting|\bxss\b|dom-based xss|stored xss|execution of arbitrary client-side code|dangerouslysetinnerhtml", "xss"),
    (r"\bcsrf\b|cross-site request forgery", "csrf"),
    (r"xml external entit|\bxxe\b", "xxe"),
    (r"deserialization.*untrusted|unsafe deserialization|pickle\.loads|yaml\.load\b", "insecure-deserialization"),

    # Crypto / TLS
    (r"weak-sensitive-data-hashing|insecure.*hash|\bmd5\b|\bsha1\b|weak.*crypto|insufficient.*entropy|weak random|insecure randomness", "insecure-crypto"),
    (r"certificate validation|ssl/tls|server certificate|hostname verification|insecure tls|tls.*disabled|verify=false", "insecure-tls"),

    # Info disclosure
    (r"stack-trace-exposure|stack trace.*expose|sensitive data.*log|information disclosure|verbose error|leaks version information|server leaks|x-powered-by", "info-disclosure"),
    (r"flask-debug|debug mode|debug feature is deactivated|flask_debug|debug=true", "debug-enabled"),

    # Workflow / CI-CD misconfig
    (r"missing-workflow-permissions|github_token|workflow does not limit the permissions|excessive.*permissions.*workflow", "ci-misconfiguration"),

    # Docker / container misconfig
    (r"runs with .root. as the default|copying recursively|granting write access to others|debug feature is deactivated before delivering|run as root|privileged container|exposed docker socket", "container-misconfiguration"),
    (r"--only-binary|locking resolved versions|lock file.*missing|dependency versions are not predictable|unpinned dependency|floating version", "dependency-pinning"),

    # Web app config
    (r"permissive cors|cors policy|access-control-allow-origin.*\*", "cors-misconfiguration"),
    (r"specify the http methods|http methods this route should accept|missing http method restriction", "http-method-misconfiguration"),

    # Date/time correctness (not strictly security, but flagged by Sonar)
    (r"datetime\.utcnow|utcnow", "code-quality"),

    # Constant/dead-code logic issues
    (r"boolean value is constant|expression.*constant|unreachable code|dead code|unused variable|unused import", "code-quality"),

    # React / frontend quality (SonarCloud JS rules) — not security findings.
    # Classified to their own categories (rather than the generic
    # "code-quality" catch-all) where the issue type is distinct enough to
    # be useful on its own; genuine misc code smells still fall into
    # "code-quality" below.
    (r"is missing in props validation", "react-props-validation"),
    (r"form label must be associated with a control", "accessibility"),
    (r"value prop to the context provider changes every render", "react-performance"),

    # Misc JS code smells — maintainability only, no security signal.
    (r"nested ternary|imported multiple times|prefer `?number\.parse|unexpected negated condition|ambiguous spacing", "code-quality"),

    # ZAP baseline scan's standard alert catalog — these names are part of a
    # stable, well-known rule set used across virtually every ZAP baseline
    # scan, so this is added proactively rather than waiting for real output.
    # NOT yet validated against an actual scan of this app — check stderr
    # for "unmatched rule_id" warnings on the first real run.
    (r"content security policy|csp header not set|x-frame-options|x-content-type-options|strict-transport-security|permissions policy header|anti-clickjacking|cross-origin-embedder-policy|cross-origin-resource-policy|cross-origin-opener-policy", "missing-security-headers"),
    (r"cookie.*without.*secure|cookie.*without.*httponly|cookie no httponly flag|cookie without.*samesite|samesite attribute", "insecure-cookie"),
    (r"storable and cacheable|cache-control directives|retrieved from cache", "insecure-caching"),

    # Purely informational ZAP findings — not a vulnerability, just an FYI
    # note about the application (e.g. "this looks like a modern SPA").
    # Kept as its own category rather than uncategorized, but with a
    # recommendation that says plainly there's nothing to fix.
    (r"modern web application", "informational-finding"),
]

DEFAULT_CATEGORY = "uncategorized"


def classify_category(rule_id, message):
    haystack = f"{rule_id or ''} {message or ''}".lower()
    for pattern, category in CATEGORY_RULES:
        if re.search(pattern, haystack):
            return category

    # This codebase's rule_id surface is fixed and was fully mapped against
    # real scan output (67/67 findings categorized as of 2026-06-20). An
    # unmatched rule_id here is therefore more likely a gap in CATEGORY_RULES
    # than genuinely new code appearing — surface it loudly in CI logs
    # rather than letting it sit silently in the JSON output.
    print(
        f"WARNING: unmatched rule_id/message, falling back to '{DEFAULT_CATEGORY}'. "
        f"rule_id={rule_id!r} message={(message or '')[:100]!r}. "
        f"Add a matching pattern to CATEGORY_RULES in classify_finding.py.",
        file=sys.stderr,
    )
    return DEFAULT_CATEGORY


# ─────────────────────────────────────────────────────────────────
# CONFIDENCE: derived from each tool's own severity/validity signal,
# since none of the 3 tools expose a unified "confidence" field.
# Mapped to a 3-level scale: high, medium, low.
# ─────────────────────────────────────────────────────────────────

# GitGuardian: validity field is the strongest direct signal available
# ("invalid" means GG actively checked it against the real provider API
# and confirmed it doesn't work — e.g. the Stripe key in this repo).
GITGUARDIAN_VALIDITY_CONFIDENCE = {
    "valid": "high",
    "invalid": "low",
    "no_checker": "medium",   # no live API check exists for this secret type
    "unknown": "medium",
    "failed_to_check": "medium",
}

# SonarCloud: impacts[].severity vocabulary (confirmed from real data:
# BLOCKER, HIGH, MEDIUM, LOW)
SONARCLOUD_SEVERITY_CONFIDENCE = {
    "blocker": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",
}

# CodeQL: SARIF "level" field (note, warning, error)
CODEQL_LEVEL_CONFIDENCE = {
    "error": "high",
    "warning": "medium",
    "note": "medium",   # CodeQL's security queries commonly report at "note"
                          # level even for real findings like sql-injection,
                          # so this is not downgraded to "low" by default.
}

# Snyk: native CLI JSON output (`snyk container test --json-file-output`)
# uses its own severity vocabulary (low/medium/high/critical), distinct
# from CodeQL's SARIF "level" field — do not conflate the two.
SNYK_SEVERITY_CONFIDENCE = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def classify_confidence(tool, severity):
    sev = (severity or "").lower()
    if tool == "gitguardian":
        return GITGUARDIAN_VALIDITY_CONFIDENCE.get(sev, "medium")
    if tool == "sonarcloud":
        return SONARCLOUD_SEVERITY_CONFIDENCE.get(sev, "medium")
    if tool == "codeql":
        return CODEQL_LEVEL_CONFIDENCE.get(sev, "medium")
    if tool == "snyk":
        return SNYK_SEVERITY_CONFIDENCE.get(sev, "medium")
    return "medium"


# ─────────────────────────────────────────────────────────────────
# TYPE: coarse classification of *what kind* of finding this is,
# independent of severity. Lets a consumer filter to "security only"
# without maintaining a separate allowlist of category names, and
# keeps a tool's native severity (e.g. SonarCloud's MEDIUM/BLOCKER)
# from being mistaken for a security-relevance signal — severity and
# type are orthogonal (a BLOCKER-severity prop-types warning is still
# a quality issue, not a security one).
# ─────────────────────────────────────────────────────────────────
TYPE_BY_CATEGORY = {
    "secret-exposure": "security",
    "vulnerable-dependency": "security",
    "license-risk": "security",
    "injection": "security",
    "path-traversal": "security",
    "ssrf": "security",
    "client-side-request-forgery": "security",
    "xss": "security",
    "csrf": "security",
    "xxe": "security",
    "insecure-deserialization": "security",
    "insecure-crypto": "security",
    "insecure-tls": "security",
    "info-disclosure": "security",
    "debug-enabled": "security",
    "ci-misconfiguration": "security",
    "container-misconfiguration": "security",
    "dependency-pinning": "security",
    "network-exposure": "security",
    "cors-misconfiguration": "security",
    "http-method-misconfiguration": "security",
    "code-quality": "quality",
    "react-props-validation": "quality",
    "accessibility": "accessibility",
    "react-performance": "performance",
    "missing-security-headers": "security",
    "insecure-cookie": "security",
    "insecure-caching": "security",
    "informational-finding": "quality",

    # Infrastructure (kube-linter). Populated via direct check-name lookup
    # in normalize_kubelinter.py, not regex matching — listed here anyway
    # since remediation_guide/grouping look these up by category name
    # regardless of how the category was determined.
    "privileged-container": "security",
    "run-as-root": "security",
    "missing-resource-limits": "security",
    "writable-root-filesystem": "security",
    "default-service-account-usage": "security",
    "secret-in-env-var": "security",
    "missing-health-probe": "quality",
    "mutable-image-tag": "security",
    "excessive-exposure": "security",
    "host-namespace-sharing": "security",
    "privilege-escalation": "security",
    "excessive-capabilities": "security",
    "missing-pod-isolation": "security",
    "job-lifecycle": "quality",

    # Terraform (Checkov, GCP provider). Populated via direct check-id
    # lookup in normalize_checkov.py, not regex matching — same reasoning
    # as the kube-linter block above (Checkov's OSS output has no native
    # severity field either; see normalize_checkov.py's docstring).
    "open-firewall-rule": "security",
    "workload-identity-disabled": "security",
    "legacy-cluster-auth": "security",
    "missing-cluster-logging-monitoring": "security",
    "missing-network-hardening": "security",
    "missing-rbac-hardening": "security",
    "missing-binary-authorization": "security",
    "excessive-iam-privilege": "security",
    "public-storage-bucket-risk": "security",
    "missing-storage-access-logging": "security",
    "missing-bucket-versioning": "quality",
    "node-hardening-gap": "security",
    "node-pool-maintenance": "quality",

    # Kyverno. Several Kyverno checks reuse EXISTING categories above
    # (privileged-container, host-namespace-sharing, excessive-capabilities,
    # privilege-escalation, run-as-root, missing-resource-limits,
    # missing-pod-isolation) since they assess the exact same underlying
    # concept kube-linter/checkov already cover — same reasoning as
    # checkov's CKV_GCP_12 reusing missing-pod-isolation. Only genuinely
    # new concepts get a new category here. Populated via direct
    # (policy, rule) lookup in normalize_kyverno.py, not regex matching.
    "host-path-mount": "security",
    "host-process-container": "security",
    "unmasked-proc-mount": "security",
    "selinux-override": "security",
    "unrestricted-apparmor-profile": "security",
    "missing-seccomp-profile": "security",
    "unrestricted-volume-types": "security",
    "unsigned-container-image": "security",

    # KubeArmor. Unlike kube-linter/checkov/kyverno (fixed, known check
    # catalogs -> direct ID lookup), KubeArmor's PolicyName is whatever
    # arbitrary KubeArmorPolicy/KubeArmorHostPolicy someone deployed on the
    # live cluster — unknowable in advance. Categorized by Operation
    # instead (Process/File/Network/Syscall), a small fixed vocabulary
    # KubeArmor itself defines — see normalize_kubearmor.py.
    "unauthorized-process-execution": "security",
    "unauthorized-file-access": "security",
    "unauthorized-network-activity": "security",
    "unauthorized-syscall": "security",
}

# Fail-safe default for "uncategorized" (and any category someone adds to
# CATEGORY_RULES/RECOMMENDATIONS_BY_CATEGORY but forgets to add here):
# treat it as security rather than silently dropping it from a
# security-filtered view. Better to over-include an unclassified finding
# than to hide a potential real vulnerability behind a missing mapping.
DEFAULT_TYPE = "security"


def classify_type(category):
    return TYPE_BY_CATEGORY.get(category, DEFAULT_TYPE)


# ─────────────────────────────────────────────────────────────────
# RECOMMENDATION: short, generic fix-it text keyed by category.
# Intentionally generic (category-level, not rule-specific) since
# rule-specific remediation text would require a much larger mapping
# table than can be grounded in the data observed so far.
# ─────────────────────────────────────────────────────────────────
RECOMMENDATIONS_BY_CATEGORY = {
    "secret-exposure": "Remove the hardcoded credential from source control, rotate it at the provider, and load it from a secret manager or environment variable at runtime.",
    "vulnerable-dependency": "Upgrade the affected package or base image to a patched version. If no fix is available yet, check whether the vulnerable code path is actually reachable in this image and document a time-boxed exception (e.g. a Snyk ignore policy) rather than leaving it unaddressed indefinitely.",
    "license-risk": "Review this dependency's license against your project's actual license policy. Either replace the dependency with one under an acceptable license, or get explicit sign-off (e.g. from legal) before shipping it — this is a compliance decision, not something to silently ignore.",
    "injection": "Use parameterized queries or an ORM instead of building commands/queries via string concatenation with user input.",
    "path-traversal": "Validate and sanitize user-supplied paths against an allowlist; resolve and confirm the final path stays within an intended base directory.",
    "ssrf": "Validate and allowlist destination hosts/URLs before making outbound requests; never construct request URLs directly from unsanitized user input.",
    "client-side-request-forgery": "Validate and allowlist the destination path/host before using user-controlled data to build a client-side (browser) request URL; don't interpolate unsanitized input directly into fetch/XHR calls.",
    "xss": "Escape or sanitize user-supplied data before rendering it in HTML/JS output; use the framework's built-in templating auto-escaping.",
    "csrf": "Implement CSRF tokens on state-changing requests and verify the token server-side before processing the request.",
    "xxe": "Disable external entity resolution in the XML parser; use a parser configuration that rejects DTDs/external entities by default.",
    "insecure-deserialization": "Avoid deserializing untrusted data with formats that can execute code (e.g. pickle); use a safe format like JSON, or validate/sign the payload before deserializing.",
    "insecure-crypto": "Replace the weak hashing algorithm (e.g. MD5/SHA1) with a modern algorithm appropriate for the use case (e.g. bcrypt/Argon2 for passwords, SHA-256+ for integrity).",
    "insecure-tls": "Enable certificate validation on the TLS connection; do not disable verification even for internal/test traffic.",
    "info-disclosure": "Avoid returning stack traces or internal error details to end users; log details server-side and return a generic error message.",
    "debug-enabled": "Disable debug mode in production deployments; gate it behind an environment-specific configuration flag.",
    "ci-misconfiguration": "Add an explicit `permissions:` block to the workflow/job scoped to only what's required (e.g. `contents: read`).",
    "container-misconfiguration": "Review the Dockerfile instruction flagged; avoid running as root, avoid broad recursive COPY, and pin dependency versions explicitly.",
    "dependency-pinning": "Add a lock file (e.g. uv.lock, poetry.lock) and avoid installing packages without pinned, resolved versions.",
    "network-exposure": "Avoid binding services to 0.0.0.0 in production; bind to a specific interface or rely on a reverse proxy/load balancer.",
    "cors-misconfiguration": "Restrict CORS to a specific allowlist of trusted origins instead of a permissive wildcard policy.",
    "http-method-misconfiguration": "Explicitly declare the allowed HTTP methods for this route instead of accepting all methods by default.",
    "code-quality": "Review the flagged code for correctness; this is a maintainability/quality finding rather than a direct security vulnerability.",
    "react-props-validation": "Add PropTypes (or migrate to TypeScript) for this component's props so an invalid prop shape is caught during development instead of failing silently at runtime.",
    "accessibility": "Associate the form label with its control via `htmlFor`/`id` (or by wrapping the input in the label), and verify the element exposes the ARIA attributes assistive technologies rely on.",
    "react-performance": "Wrap the value passed to the Context provider in `useMemo` so it keeps a stable identity across renders and doesn't trigger unnecessary re-renders in consumers.",
    "missing-security-headers": "Add the missing HTTP security header (e.g. Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security) at the web server, reverse proxy, or application framework level.",
    "insecure-cookie": "Set the Secure and HttpOnly flags on all session/auth cookies, and set SameSite appropriately to reduce CSRF exposure.",
    "insecure-caching": "Set Cache-Control: no-store (and Pragma: no-cache for older clients) on any response containing sensitive or user-specific data; static assets can remain cacheable.",
    "informational-finding": "No action needed — this is an FYI-level observation about the application, not a vulnerability.",

    "privileged-container": "Remove `privileged: true` from the container's securityContext. Privileged containers have unrestricted host access — grant only the specific Linux capabilities actually needed instead.",
    "run-as-root": "Set `runAsNonRoot: true` (and a non-zero `runAsUser`) in the pod or container securityContext, so the process can't run as root even if the image itself doesn't define a non-root user.",
    "missing-resource-limits": "Set explicit CPU/memory `requests` and `limits` on every container. Without limits, a single misbehaving pod can exhaust node resources and affect other workloads.",
    "writable-root-filesystem": "Set `readOnlyRootFilesystem: true` in the container's securityContext, and mount an explicit writable volume for any path that genuinely needs write access.",
    "default-service-account-usage": "Create a dedicated ServiceAccount for this workload instead of relying on the namespace's default one — this is what makes Workload Identity (or any per-workload IAM binding) possible to scope correctly.",
    "secret-in-env-var": "Mount the secret as a file or use `secretKeyRef` in an env var's `valueFrom`, rather than a raw secret value directly in the env var — raw values are visible via `kubectl describe pod` and process inspection.",
    "missing-health-probe": "Add `livenessProbe`/`readinessProbe` so Kubernetes can detect and recover from a hung or not-yet-ready container, instead of routing traffic to it regardless.",
    "mutable-image-tag": "Pin the image to a specific, immutable tag or digest rather than `:latest` — without this, you can't reliably audit or reproduce exactly what's running.",
    "excessive-exposure": "Confirm this Service's exposure (NodePort/LoadBalancer) is actually intended for this workload — prefer ClusterIP plus an Ingress/Gateway for anything that doesn't need to be reachable this directly.",
    "host-namespace-sharing": "Remove `hostNetwork`/`hostPID`/`hostIPC: true` unless this workload genuinely needs direct access to the host's namespaces — sharing them removes the isolation a container is supposed to provide.",
    "privilege-escalation": "Set `allowPrivilegeEscalation: false` in the container's securityContext, so a process can't gain more privileges than its parent (e.g. via a setuid binary).",
    "excessive-capabilities": "Drop all Linux capabilities (`drop: [\"ALL\"]`) and add back only the specific ones this container actually needs, rather than keeping the default set.",
    "missing-pod-isolation": "Add a NetworkPolicy scoping which pods/namespaces can actually reach this workload, rather than leaving it reachable from anything else in the cluster by default.",
    "job-lifecycle": "Set `spec.ttlSecondsAfterFinished` on Jobs so completed/failed Job objects (and their pods) are automatically cleaned up instead of accumulating indefinitely in the cluster.",

    "open-firewall-rule": "Restrict the firewall rule's `source_ranges` to specific known CIDR blocks instead of 0.0.0.0/0, and scope `allow` blocks to only the ports actually required rather than a full port range.",
    # Directly corresponds to this project's own already-confirmed real
    # finding (Workload Identity disabled cluster-wide, bare default SA) —
    # this is the Terraform-level root cause: node_config's
    # workload_metadata_config.mode is set to the legacy GCE_METADATA value
    # instead of GKE_METADATA, which is what Workload Identity requires.
    "workload-identity-disabled": "Set `workload_metadata_config.mode = \"GKE_METADATA\"` on the node pool and enable `workload_identity_config` on the cluster, so pods can use scoped per-workload IAM identities instead of inheriting the node's Compute Engine service account.",
    "legacy-cluster-auth": "Set `enable_legacy_abac = false` and `master_auth.client_certificate_config.issue_client_certificate = false`; rely on Kubernetes RBAC and IAM-based authentication instead of these deprecated mechanisms.",
    "missing-cluster-logging-monitoring": "Set `logging_service` and `monitoring_service` to their Stackdriver/Cloud Operations values (e.g. \"logging.googleapis.com/kubernetes\", \"monitoring.googleapis.com/kubernetes\") instead of \"none\", so cluster activity is actually auditable.",
    "missing-network-hardening": "Enable the flagged cluster-level network control (master authorized networks, alias IP ranges, or VPC flow logs/intranode visibility) — each narrows the cluster's network attack surface or improves traffic visibility.",
    "missing-rbac-hardening": "Configure `authenticator_groups_config` to manage cluster RBAC access via Google Groups instead of individually-granted IAM bindings, for centralized access review.",
    "missing-binary-authorization": "Enable Binary Authorization on the cluster so only signed, attested container images can be deployed.",
    "excessive-iam-privilege": "Replace the basic role (Owner/Editor/Viewer) or service-account-impersonation-capable role with the narrowest predefined or custom role that covers the actual required permissions — Owner on a Compute Engine default service account is effectively full project compromise if that SA's key or node is ever exposed.",
    "public-storage-bucket-risk": "Enable `uniform_bucket_level_access` and set the bucket's public access prevention to enforced, so objects can't be made public via legacy per-object ACLs even if a future config change tries to.",
    "missing-storage-access-logging": "Configure a `logging` block on the bucket pointing to a separate log-sink bucket, so object access is auditable.",
    "missing-bucket-versioning": "Enable object versioning on the bucket so an accidental overwrite or delete can be recovered rather than being permanent.",
    "node-hardening-gap": "Enable Shielded VM Secure Boot (`shielded_instance_config.enable_secure_boot = true`) on the node pool to prevent loading unsigned/malicious boot components.",
    "node-pool-maintenance": "Enable `management.auto_repair` and `management.auto_upgrade` on the node pool so unhealthy or outdated nodes are remediated automatically instead of silently drifting.",

    "host-path-mount": "Remove the hostPath volume, or replace it with a narrower-scoped alternative (ConfigMap, Secret, emptyDir, or a dedicated PVC) — hostPath gives a container direct access to the node's filesystem, which is a well-known container-escape vector.",
    "host-process-container": "Remove `securityContext.windowsOptions.hostProcess: true` — HostProcess containers run directly on the host with elevated privileges (Windows-node specific; verify this is even applicable to this cluster's node pool).",
    "unmasked-proc-mount": "Remove `securityContext.procMount: Unmasked` (or simply leave procMount unset) so /proc stays masked using Kubernetes' default, safer configuration.",
    "selinux-override": "Remove the custom `seLinuxOptions` override (type/user/role) and rely on the cluster/node's default SELinux configuration unless there's a specific, reviewed reason to deviate.",
    "unrestricted-apparmor-profile": "Set an explicit AppArmor profile (`RuntimeDefault` or a custom profile) instead of `Unconfined`, so the container gets AppArmor's mandatory access control protections.",
    "missing-seccomp-profile": "Set `securityContext.seccompProfile.type` to `RuntimeDefault` (or `Localhost` with a named profile) at the pod or container level, instead of leaving it unset/Unconfined.",
    "unrestricted-volume-types": "Use only the Pod Security Standards' allowed volume types (configMap, secret, emptyDir, persistentVolumeClaim, downwardAPI, projected, csi for specific approved drivers) instead of unrestricted volume types like hostPath or NFS.",
    # Directly closes the loop with this repo's own cosign keyless-signing
    # step in backend-ci.yaml/frontend-ci.yaml — an unsigned or
    # signature-verification-failed image reaching a Pod means the signing
    # step either didn't run, was bypassed, or the image came from
    # somewhere else entirely.
    "unsigned-container-image": "Ensure the image was built and signed by the expected CI workflow (`cosign sign --yes`, keyless via GitHub Actions OIDC) before it can be deployed. If this fires on a legitimate image, confirm the signing step in backend-ci.yaml/frontend-ci.yaml actually ran and succeeded for this exact image digest.",

    "unauthorized-process-execution": "Review the matched KubeArmorPolicy/KubeArmorHostPolicy (see the finding's policy name) — either the process execution is legitimate and the policy needs a corresponding allow rule, or it's genuinely unexpected and worth investigating as a possible compromise.",
    "unauthorized-file-access": "Review the matched policy's file rules — either add an allow rule for this legitimate access pattern, or treat it as a possible unauthorized access attempt if the path/process combination is unexpected.",
    "unauthorized-network-activity": "Review the matched policy's network rules — either the connection is expected and needs an allow rule, or it's unexpected outbound/inbound activity worth investigating (e.g. unexpected destination, port, or protocol).",
    "unauthorized-syscall": "Review the matched policy's syscall rules — confirm whether this specific syscall is genuinely needed by the workload or should be tightened further.",

    "uncategorized": "No automated category match was found for this rule_id/message. Since this codebase's rule_id surface is expected to be fixed and fully mapped, an uncategorized finding likely indicates a gap in classify_finding.py's CATEGORY_RULES rather than genuinely new code — inspect the rule_id below and add a matching pattern.",
}


def classify_recommendation(category):
    return RECOMMENDATIONS_BY_CATEGORY.get(category, RECOMMENDATIONS_BY_CATEGORY["uncategorized"])


def build_line_field(start_line, end_line):
    """Format start/end line into a single 'line' field per spec:
    '32-62' when they differ, '32' when equal, None/'' passthrough."""
    if start_line is None and end_line is None:
        return None
    if end_line is None or start_line == end_line:
        return str(start_line) if start_line is not None else (str(end_line) if end_line is not None else None)
    return f"{start_line}-{end_line}"


def classify(tool, severity, rule_id, message):
    """Convenience wrapper returning (category, type_, confidence, recommendation).

    BREAKING CHANGE: this now returns a 4-tuple instead of 3 (added
    `type_` as the second element). Any normalizer doing
    `category, confidence, recommendation = classify(...)` needs to be
    updated to `category, type_, confidence, recommendation = classify(...)`
    and to add a `"type": type_` key to its output dict.
    """
    category = classify_category(rule_id, message)
    type_ = classify_type(category)
    confidence = classify_confidence(tool, severity)
    recommendation = classify_recommendation(category)
    return category, type_, confidence, recommendation