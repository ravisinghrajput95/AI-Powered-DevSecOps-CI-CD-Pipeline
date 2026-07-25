# Release Intelligence Report

**Repository:** `ravisinghrajput95/AI-Powered-DevSecOps-CI-CD-Pipeline`
**Release Version:** `2382597af3ea184f9897d9373f10bc0b59ff083d`
**Report Generated:** 2026-07-25T14:28:38.227711+00:00
**Report ID:** `d6af1576eadedf6c`
**Components Assessed:** backend, frontend, deployed-app, infrastructure, terraform

---

## Executive Summary

**Overall Health:** CRITICAL &nbsp;|&nbsp; **Deployment Confidence:** LOW

**Dominant Risk Themes:** Privilege escalation enabled across deployed workloads, Unsigned container images in live cluster, Hardcoded secrets and credentials in source code, Severely outdated frontend/backend dependencies, Open firewall rules and excessive IAM privileges in infra, Critical OS-layer CVEs in deployed container images

This release presents a critical security posture across all five measured domains. The most urgent concern is the live deployed-app cluster: Kyverno policy enforcement confirms that privilege escalation is not blocked on any workload (26 affected locations), containers run as root, no seccomp profiles are set, and all Linux capabilities are retained — a combination that means any container breakout or code execution vulnerability immediately yields full node-level access. Compounding this, Kyverno also confirms that deployed images lack cosign signatures and digests, meaning the supply chain integrity guarantee is absent at runtime despite both images reporting SUCCESS in the supply chain verification block — the runtime policy check reveals the deployed image digests are not pinned, which is the operative fact for deployment trust. On the application layer, SonarCloud and CodeQL confirm high-confidence injection, path traversal, XSS, and SSRF vulnerabilities in the backend, alongside four occurrences of hardcoded PostgreSQL passwords (critical, BLOCKER severity). The frontend carries two critically vulnerable npm packages — axios@0.21.1 and dompurify@2.3.3 — each accumulating dozens of CVEs across prototype pollution, HTTP response splitting, XSS, and SSRF classes; both have clear upgrade paths. The backend container image carries critical OS-layer CVEs in openssl, gnutls28, krb5, expat, and zlib — packages that are foundational to TLS and authentication. Infrastructure Terraform configuration exposes unrestricted SSH, RDP, MySQL, and FTP firewall ingress rules, grants compute Owner-level IAM at project scope, and has a publicly accessible storage bucket — any one of these would be a standalone blocker in a production environment. Workload Identity is disabled, meaning all pods inherit the node's Compute Engine service account, which holds Owner-level permissions. The combination of excessive IAM, open network perimeter, and container workloads running as root with privilege escalation enabled creates a blast radius that spans the entire GCP project. Reachability, exploitability, business impact, and internet exposure are not collected by this pipeline, which limits confidence in precise prioritization but does not change the severity of the confirmed findings.

---

## Cross-Domain Analysis

### Workload Identity disabled + Owner IAM + root containers = full project blast radius

**Affected domains:** runtime_security, infrastructure_security, application_security &nbsp;|&nbsp; **Confidence:** HIGH

Terraform confirms Workload Identity (GKE Metadata Server) is disabled on the node pool, and the Compute Engine default service account holds Owner-level IAM at project scope. Kyverno confirms deployed containers run as root with privilege escalation allowed and all Linux capabilities retained. Any container escape or code execution vulnerability — several of which are confirmed in the application layer — would give an attacker root on the node, access to the node's service account token, and from there Owner-level control of the entire GCP project.

**Business impact:** Full GCP project compromise from a single container-level exploit. All data, infrastructure, and services in the project are at risk.

**Recommended action:** Immediately enable Workload Identity on the GKE cluster and node pool, replace the Owner IAM binding with a least-privilege custom role, and enforce allowPrivilegeEscalation=false and runAsNonRoot=true on all deployed workloads. These three changes together collapse the blast radius from project-wide to container-scoped.

**Evidence:** `f1f751c2ee51` (CKV_GCP_69, HIGH); `54c214b711d1` (CKV_GCP_49, CRITICAL); `0487801b1fb6` (CKV_GCP_117, CRITICAL); `f913039e3a2a` (disallow-privilege-escalation/privilege-escalation, CRITICAL); `73e307bc47c2` (disallow-privilege-escalation/autogen-privilege-escalation, CRITICAL); `55a0910c0cd3` (require-run-as-nonroot/run-as-non-root, HIGH); `79abedf3ae77` (require-run-as-nonroot/autogen-run-as-non-root, HIGH); `e9fffb850fa8` (disallow-capabilities-strict/require-drop-all, HIGH); `448a793445e1` (disallow-capabilities-strict/autogen-require-drop-all, HIGH)

### Unsigned image digests at runtime undermine supply chain SUCCESS status

**Affected domains:** supply_chain, runtime_security, container_security &nbsp;|&nbsp; **Confidence:** HIGH

The supply_chain block reports verification_status SUCCESS for both backend and frontend images. However, Kyverno's live cosign policy check reports missing digests for the exact image references deployed in the cluster. This means the images were signed at build time but are being deployed without pinned digests — the runtime policy cannot verify the signature without a digest, making the supply chain control effectively non-functional in the live environment. The mutable :latest tag finding on the infrastructure component reinforces this pattern.

**Business impact:** An attacker who can push a replacement image to the registry can deploy arbitrary code without triggering the cosign verification gate, defeating the entire supply chain integrity control.

**Recommended action:** Pin all deployed image references to their full SHA256 digest (e.g. image@sha256:...) in Kubernetes manifests. Ensure the CI pipeline writes the digest output from the build/push step directly into the Helm values or manifest before deployment, so the cosign verification policy can resolve and verify the signature.

**Evidence:** `f84f2db980d4` (verify-image-cosign/verify-cosign-keyless-signature, CRITICAL); `3f6606939177` (verify-image-cosign/autogen-verify-cosign-keyless-signature, CRITICAL); `6a3ccaf023bb` (latest-tag, MEDIUM)

### Open firewall perimeter + public storage bucket + no network policy = flat attack surface

**Affected domains:** infrastructure_security, runtime_security &nbsp;|&nbsp; **Confidence:** HIGH

Terraform confirms unrestricted ingress on SSH (0.0.0.0/0), RDP, MySQL, FTP, and HTTP port 80, with no master authorized networks and no Kubernetes NetworkPolicy. A public Cloud Storage bucket with no access prevention enforcement compounds this. The cluster has no VPC flow logs or intranode visibility, meaning lateral movement within the cluster would be undetected. Together these findings describe a network perimeter with no meaningful segmentation at any layer.

**Business impact:** Any internet-accessible service or misconfigured workload can be reached directly. Lateral movement within the cluster is unconstrained and undetected. Data in the public storage bucket is accessible to anyone.

**Recommended action:** Restrict all firewall rules to specific source CIDRs; remove or scope the allow_all rule. Enable Kubernetes NetworkPolicy and master authorized networks. Set public access prevention to enforced on the storage bucket. Enable VPC flow logs for audit visibility.

**Evidence:** `3ba928b4fd97` (CKV_GCP_88, CRITICAL); `dbbdc1cf61c2` (CKV_GCP_2, CRITICAL); `57df84a4027d` (CKV_GCP_3, CRITICAL); `189191849e41` (CKV_GCP_114, CRITICAL); `7a97a533c5a2` (CKV_GCP_12, MEDIUM); `0d8acda49a79` (CKV_GCP_20, MEDIUM); `8d32bd1d8e72` (CKV_GCP_61, MEDIUM); `53953124a35c` (CKV_GCP_23, MEDIUM); `be6a83a66fe7` (CKV_GCP_106, MEDIUM)

### Hardcoded secrets in source confirmed by three independent tools

**Affected domains:** application_security, infrastructure_security &nbsp;|&nbsp; **Confidence:** HIGH

SonarCloud (critical BLOCKER), CodeQL, and GitGuardian independently confirm hardcoded PostgreSQL passwords and a SECRET_KEY in the backend source. GitGuardian also detects username/password credentials in both frontend and backend. The SonarCloud finding has occurrence_count 4, indicating the credential appears in multiple locations. These are not theoretical — three tools with different detection mechanisms all agree, giving very high confidence the secrets are real and present in the repository.

**Business impact:** Any developer, CI runner, or attacker with repository read access can extract live database credentials. If the PostgreSQL instance is reachable (the open firewall rules make this plausible), direct database compromise is possible without any application-layer exploit.

**Recommended action:** Immediately rotate all exposed credentials (PostgreSQL password, SECRET_KEY, any username/password pairs). Remove them from source history (git filter-repo or BFG). Load secrets at runtime from a secret manager (GCP Secret Manager or Kubernetes Secrets with appropriate RBAC). Block future commits containing secrets via a pre-commit hook and GitGuardian's push protection.

**Evidence:** `049991827bea` (secrets:S6698, CRITICAL); `45577584570d` (Generic Password, MEDIUM); `00af2baa5ff3` (Username Password, MEDIUM); `ba3dc970c4bd` (python:S2068, MEDIUM); `0ad3628d28ea` (Generic Password, MEDIUM); `878a66ae7816` (Username Password, MEDIUM)

### Backend code injection vulnerabilities amplified by Flask debug mode and insecure TLS

**Affected domains:** application_security, runtime_security &nbsp;|&nbsp; **Confidence:** HIGH

SonarCloud (critical BLOCKER) and CodeQL both independently confirm OS command injection and path traversal in the backend. CodeQL additionally confirms SQL injection and SSRF. Flask debug mode is confirmed enabled (CodeQL medium, SonarCloud low), which exposes an interactive debugger that allows arbitrary Python code execution if triggered. TLS certificate validation is disabled in two locations. The combination means an attacker who reaches the backend can execute OS commands, traverse the filesystem, query the database directly, and do so over connections that cannot be authenticated by the server.

**Business impact:** Remote code execution on the backend container, with direct database access and the ability to pivot to the GCP metadata service (amplified by disabled Workload Identity controls).

**Recommended action:** Remediate injection vulnerabilities (parameterized queries, subprocess with argument lists, path allowlisting) before deployment. Disable Flask debug mode via environment-specific configuration. Enable TLS certificate validation unconditionally.

**Evidence:** `688d20fa838a` (pythonsecurity:S2076, CRITICAL); `447335a06a0f` (pythonsecurity:S2083, CRITICAL); `6f568715650c` (py/command-line-injection, MEDIUM); `757685f73438` (py/sql-injection, MEDIUM); `217911839f44` (py/flask-debug, MEDIUM); `0c9c83aacaa9` (docker:S4507, LOW); `95abf401b56f` (python:S4830, HIGH); `ff32e3378a60` (py/full-ssrf, MEDIUM); `37c28065d914` (pythonsecurity:S5144, MEDIUM)

### Severely outdated npm packages (axios, dompurify) drive frontend critical CVE cluster

**Affected domains:** application_security, container_security &nbsp;|&nbsp; **Confidence:** HIGH

axios@0.21.1 accumulates 28 findings (2 critical, multiple high/medium) spanning prototype pollution, HTTP response splitting, SSRF, CSRF, and ReDoS. dompurify@2.3.3 accumulates 22 findings (1 critical, multiple high/medium) spanning XSS, prototype pollution, and template injection — directly undermining the library's core purpose of sanitizing HTML. Both have clear upgrade paths documented in remediation_notes. SonarCloud independently confirms an XSS vulnerability in the frontend JS code, meaning the application layer compounds the dependency-layer XSS risk.

**Business impact:** Client-side code execution, credential theft, CSRF, and SSRF from the frontend. The dompurify vulnerabilities are particularly high-impact because the library is specifically used to prevent XSS — its compromise means the XSS defense layer is absent.

**Recommended action:** Upgrade axios to >=1.16.0 (or >=0.32.0 for the 0.x line) and dompurify to >=3.4.12 to resolve all known CVEs in a single upgrade per package. Also upgrade lodash to >=4.18.1 and moment to >=2.29.4. Add npm audit to the CI gate to prevent regression.

**Evidence:** `0dc16d7ed2e9` (SNYK-JS-AXIOS-16298058, CRITICAL); `a7b165255456` (SNYK-JS-AXIOS-16299904, CRITICAL); `82d7f2881d4c` (SNYK-JS-DOMPURIFY-8318045, CRITICAL); `6751a218019c` (jssecurity:S5696, CRITICAL); `472ae7a3640e` (SNYK-JS-AXIOS-15252993, HIGH); `301f4d9e8a0f` (SNYK-JS-AXIOS-1579269, HIGH); `afac6e0ca60a` (SNYK-JS-AXIOS-15969258, HIGH); `9eda1fcf005c` (SNYK-JS-DOMPURIFY-7984421, HIGH)

### Critical OS-layer CVEs in backend container image on live cryptographic and auth libraries

**Affected domains:** container_security, application_security &nbsp;|&nbsp; **Confidence:** HIGH

The backend container image carries critical CVEs in openssl (4 occurrences), gnutls28 (2 critical CVEs), krb5 (critical, 11 occurrences), expat (2 critical), and zlib (critical, 5 occurrences). These are foundational system libraries used for TLS, Kerberos authentication, and XML parsing — not peripheral utilities. The application-layer finding of disabled TLS certificate validation (insecure-tls) means the application is already not fully leveraging TLS integrity, and the underlying TLS library itself is vulnerable.

**Business impact:** Cryptographic library vulnerabilities in a live container can enable TLS interception, authentication bypass, and memory corruption attacks against the backend service. Combined with the application-layer TLS misconfiguration, the end-to-end security of all backend communications is compromised.

**Recommended action:** Rebuild the backend container image from an updated Debian 12 base image (or use a minimal distroless base). Upgrade openssl, gnutls28, krb5, expat, and zlib to their patched versions as documented in remediation_notes. Integrate container image scanning into the CI pipeline as a blocking gate.

**Evidence:** `80c766bd7abd` (SNYK-DEBIAN12-OPENSSL-15969314, CRITICAL); `9aeed721127a` (SNYK-DEBIAN12-GNUTLS28-16344303, CRITICAL); `903cec21ca4e` (SNYK-DEBIAN12-GNUTLS28-16344325, CRITICAL); `971307a2fb61` (SNYK-DEBIAN12-KRB5-7411315, CRITICAL); `083d9d82d66b` (SNYK-DEBIAN12-ZLIB-6008963, CRITICAL); `406f0f4dac9b` (SNYK-DEBIAN12-EXPAT-7855502, CRITICAL); `afabe834cfa4` (SNYK-DEBIAN12-EXPAT-7855503, CRITICAL); `95abf401b56f` (python:S4830, HIGH)

---

## Top Risks

### Risk 1: Privilege escalation + root containers + Owner IAM = full GCP project compromise path

**Confidence:** HIGH

**Impact:** A single exploitable vulnerability in any deployed container (several confirmed at critical/high severity) can yield root on the node, access to the node's Compute Engine service account with Owner-level IAM, and full control of the GCP project — all data, infrastructure, and services.

**Why it matters:** This is not a theoretical chain: each link is confirmed by a separate tool at high confidence. Kyverno confirms privilege escalation is allowed and containers run as root in the live cluster. Checkov confirms the node pool lacks Workload Identity and the service account holds Owner IAM. Application-layer tools confirm multiple exploitable injection and code execution vulnerabilities. The blast radius is the entire GCP project.

**Recommended action:** Block deployment until: (1) allowPrivilegeEscalation=false and runAsNonRoot=true are enforced on all workloads, (2) Workload Identity is enabled and the node pool's service account is replaced with a least-privilege identity, (3) the Owner IAM binding is removed and replaced with a scoped role.

**Evidence:** `f913039e3a2a` (disallow-privilege-escalation/privilege-escalation, CRITICAL); `73e307bc47c2` (disallow-privilege-escalation/autogen-privilege-escalation, CRITICAL); `55a0910c0cd3` (require-run-as-nonroot/run-as-non-root, HIGH); `79abedf3ae77` (require-run-as-nonroot/autogen-run-as-non-root, HIGH); `f1f751c2ee51` (CKV_GCP_69, HIGH); `54c214b711d1` (CKV_GCP_49, CRITICAL); `0487801b1fb6` (CKV_GCP_117, CRITICAL); `688d20fa838a` (pythonsecurity:S2076, CRITICAL); `447335a06a0f` (pythonsecurity:S2083, CRITICAL)

### Risk 2: Hardcoded PostgreSQL credentials confirmed by three independent tools

**Confidence:** HIGH

**Impact:** Live database credentials are present in the repository and accessible to anyone with read access. If the database is reachable (open firewall rules make this plausible), direct database compromise is possible without any application exploit.

**Why it matters:** SonarCloud (critical BLOCKER, 4 occurrences), CodeQL, and GitGuardian all independently confirm the same class of finding. Three-tool agreement at high confidence eliminates false-positive risk. The open MySQL firewall rule (0.0.0.0/0) means the database may be directly internet-accessible with these credentials.

**Recommended action:** Rotate all exposed credentials immediately. Remove from source history. Load secrets from GCP Secret Manager at runtime. Close the unrestricted MySQL firewall rule. These actions are independent of the deployment decision and should happen now regardless.

**Evidence:** `049991827bea` (secrets:S6698, CRITICAL); `3ba928b4fd97` (CKV_GCP_88, CRITICAL); `45577584570d` (Generic Password, MEDIUM); `00af2baa5ff3` (Username Password, MEDIUM); `ba3dc970c4bd` (python:S2068, MEDIUM)

### Risk 3: Unsigned/unverified container images deployed to live cluster

**Confidence:** HIGH

**Impact:** The cosign image verification policy is non-functional at runtime because deployed images lack pinned digests. An attacker with registry write access can substitute a malicious image without triggering any verification gate.

**Why it matters:** The supply_chain block reports SUCCESS, but Kyverno's live policy check reveals the deployed image references are missing digests — the verification cannot succeed without a digest to resolve the signature against. This is a runtime fact that overrides the build-time status. The mutable :latest tag finding confirms the root cause.

**Recommended action:** Pin all deployed image references to their SHA256 digest. Update CI to write the digest into manifests/Helm values at build time. Verify the Kyverno cosign policy passes before considering the supply chain control effective.

**Evidence:** `f84f2db980d4` (verify-image-cosign/verify-cosign-keyless-signature, CRITICAL); `3f6606939177` (verify-image-cosign/autogen-verify-cosign-keyless-signature, CRITICAL); `6a3ccaf023bb` (latest-tag, MEDIUM)

### Risk 4: Backend OS command injection and path traversal confirmed at critical severity

**Confidence:** HIGH

**Impact:** Attackers can execute arbitrary OS commands and traverse the filesystem on the backend container. Combined with Flask debug mode being enabled, this can escalate to interactive remote code execution.

**Why it matters:** SonarCloud rates these BLOCKER (critical) with high confidence. CodeQL independently confirms command-line injection and path injection. Two tools, same root cause, high confidence — this is not a scanner artifact. Flask debug mode (confirmed by CodeQL) provides an interactive Python debugger that turns any unhandled exception into a code execution primitive.

**Recommended action:** Remediate injection vulnerabilities using parameterized inputs and path allowlisting before deployment. Disable Flask debug mode via environment configuration. These are blocking issues for production deployment.

**Evidence:** `688d20fa838a` (pythonsecurity:S2076, CRITICAL); `447335a06a0f` (pythonsecurity:S2083, CRITICAL); `6f568715650c` (py/command-line-injection, MEDIUM); `9de17c0300aa` (py/path-injection, MEDIUM); `217911839f44` (py/flask-debug, MEDIUM); `0c9c83aacaa9` (docker:S4507, LOW)

### Risk 5: Open firewall rules expose SSH, RDP, MySQL, and FTP to 0.0.0.0/0

**Confidence:** HIGH

**Impact:** The GCP compute firewall allows unrestricted internet access to SSH, RDP, MySQL, FTP, and HTTP port 80. Any service or database listening on these ports is directly internet-accessible.

**Why it matters:** Checkov confirms these at critical and high severity with high confidence. The MySQL exposure is directly correlated with the hardcoded database credentials (RISK-002) — together they represent a direct path to database compromise from the internet. The SSH/RDP exposure means any credential leak or brute-force attack can yield node-level access.

**Recommended action:** Restrict all firewall source_ranges to specific known CIDR blocks. Remove or replace the allow_all rule. Scope allow blocks to only required ports. This is a blocking infrastructure change.

**Evidence:** `3ba928b4fd97` (CKV_GCP_88, CRITICAL); `dbbdc1cf61c2` (CKV_GCP_2, CRITICAL); `57df84a4027d` (CKV_GCP_3, CRITICAL); `382c6fe86e55` (CKV_GCP_77, HIGH); `e5f32d7b4723` (CKV_GCP_75, HIGH); `be6a83a66fe7` (CKV_GCP_106, MEDIUM)

### Risk 6: Frontend axios@0.21.1 and dompurify@2.3.3 carry critical CVEs with clear upgrade paths

**Confidence:** HIGH

**Impact:** axios carries 2 critical CVEs (HTTP response splitting, prototype pollution) and 8+ high CVEs. dompurify — the library specifically used to prevent XSS — carries 1 critical CVE (prototype pollution) and multiple high/medium XSS CVEs, meaning the XSS defense layer is itself compromised.

**Why it matters:** Both packages have documented fixed versions. Upgrading axios to >=1.16.0 and dompurify to >=3.4.12 resolves all known CVEs in each package in a single operation. The risk of not upgrading is concrete: a compromised XSS sanitizer in a web application is a direct path to client-side code execution.

**Recommended action:** Upgrade axios to >=1.16.0 and dompurify to >=3.4.12. Also upgrade lodash to >=4.18.1 and moment to >=2.29.4. These are application-layer changes with low deployment risk and high security return.

**Evidence:** `0dc16d7ed2e9` (SNYK-JS-AXIOS-16298058, CRITICAL); `a7b165255456` (SNYK-JS-AXIOS-16299904, CRITICAL); `82d7f2881d4c` (SNYK-JS-DOMPURIFY-8318045, CRITICAL); `9eda1fcf005c` (SNYK-JS-DOMPURIFY-7984421, HIGH); `472ae7a3640e` (SNYK-JS-AXIOS-15252993, HIGH); `6751a218019c` (jssecurity:S5696, CRITICAL)

### Risk 7: Critical OS-layer CVEs in backend container image on TLS and auth libraries

**Confidence:** HIGH

**Impact:** The backend container image runs with critical vulnerabilities in openssl, gnutls28, krb5, expat, and zlib — libraries that underpin all TLS connections and Kerberos authentication. Memory corruption and authentication bypass are confirmed vulnerability classes.

**Why it matters:** These are not application-layer dependencies that can be patched in requirements.txt — they are OS-layer packages in the container base image. The application-layer finding of disabled TLS certificate validation means the application is already not fully leveraging TLS integrity, and the underlying library is also vulnerable. Patched versions exist for all affected packages.

**Recommended action:** Rebuild the backend container from an updated Debian 12 base image with patched system packages. Consider migrating to a distroless or minimal base image to reduce the OS-layer attack surface. Add container image scanning as a CI blocking gate.

**Evidence:** `80c766bd7abd` (SNYK-DEBIAN12-OPENSSL-15969314, CRITICAL); `9aeed721127a` (SNYK-DEBIAN12-GNUTLS28-16344303, CRITICAL); `903cec21ca4e` (SNYK-DEBIAN12-GNUTLS28-16344325, CRITICAL); `971307a2fb61` (SNYK-DEBIAN12-KRB5-7411315, CRITICAL); `083d9d82d66b` (SNYK-DEBIAN12-ZLIB-6008963, CRITICAL); `406f0f4dac9b` (SNYK-DEBIAN12-EXPAT-7855502, CRITICAL); `afabe834cfa4` (SNYK-DEBIAN12-EXPAT-7855503, CRITICAL)

### Risk 8: Public Cloud Storage bucket with no access prevention or access logging

**Confidence:** HIGH

**Impact:** The GCS bucket has public access prevention not enforced and uniform bucket-level access disabled, meaning objects can be made publicly accessible via legacy per-object ACLs. Access is not logged, so any data exfiltration would be undetected.

**Why it matters:** Checkov confirms both the public access prevention gap (critical) and the missing access logging (medium) at high confidence. Without access logging, there is no audit trail for data access. Without access prevention enforcement, a single misconfigured object ACL exposes data publicly.

**Recommended action:** Set public_access_prevention = enforced and enable uniform_bucket_level_access on the storage bucket. Configure a logging block pointing to a separate log-sink bucket. These are Terraform changes with no application impact.

**Evidence:** `189191849e41` (CKV_GCP_114, CRITICAL); `724685b547f7` (CKV_GCP_29, HIGH); `354070e54e2f` (CKV_GCP_62, MEDIUM)

---

## Highest Priority Actions

### Action 1: Rotate all hardcoded credentials and remove from source history

**Estimated complexity:** MEDIUM &nbsp;|&nbsp; **Dependencies:** none

Three independent tools confirm live database credentials and a SECRET_KEY are present in the repository. This action is independent of the deployment decision and must happen immediately — the credentials are already exposed regardless of whether this release deploys.

**Expected risk reduction:** Eliminates direct database compromise risk from credential exposure. Removes the most immediately actionable attack vector.

**Evidence:** `049991827bea` (secrets:S6698, CRITICAL); `45577584570d` (Generic Password, MEDIUM); `00af2baa5ff3` (Username Password, MEDIUM); `ba3dc970c4bd` (python:S2068, MEDIUM); `0ad3628d28ea` (Generic Password, MEDIUM); `878a66ae7816` (Username Password, MEDIUM)

### Action 2: Enforce allowPrivilegeEscalation=false, runAsNonRoot=true, and drop ALL capabilities on all deployed workloads

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

Kyverno confirms these controls are absent across all deployed workloads (26 locations for the autogen rules). These are securityContext fields that can be set without application code changes. They are the primary control preventing container-level exploits from escalating to node-level access.

**Expected risk reduction:** Collapses the blast radius of any container-level exploit from node-wide to container-scoped. Directly addresses RISK-001 and CORR-001.

**Evidence:** `f913039e3a2a` (disallow-privilege-escalation/privilege-escalation, CRITICAL); `73e307bc47c2` (disallow-privilege-escalation/autogen-privilege-escalation, CRITICAL); `55a0910c0cd3` (require-run-as-nonroot/run-as-non-root, HIGH); `79abedf3ae77` (require-run-as-nonroot/autogen-run-as-non-root, HIGH); `e9fffb850fa8` (disallow-capabilities-strict/require-drop-all, HIGH); `448a793445e1` (disallow-capabilities-strict/autogen-require-drop-all, HIGH)

### Action 3: Enable Workload Identity on GKE cluster and replace Owner IAM binding with least-privilege role

**Estimated complexity:** MEDIUM &nbsp;|&nbsp; **Dependencies:** ACT-002

Workload Identity disabled means all pods inherit the node's Compute Engine service account, which holds Owner-level IAM. This is the mechanism by which a container escape becomes a full GCP project compromise. Enabling Workload Identity and scoping the service account are Terraform changes.

**Expected risk reduction:** Eliminates the path from container escape to GCP project Owner access. Reduces blast radius from project-wide to workload-scoped.

**Evidence:** `f1f751c2ee51` (CKV_GCP_69, HIGH); `54c214b711d1` (CKV_GCP_49, CRITICAL); `0487801b1fb6` (CKV_GCP_117, CRITICAL)

### Action 4: Restrict GCP firewall rules — remove allow_all, scope to specific CIDRs and required ports only

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** ACT-001

Unrestricted ingress on SSH, RDP, MySQL, FTP, and HTTP port 80 from 0.0.0.0/0 is confirmed by Checkov at critical severity. The MySQL exposure directly amplifies the hardcoded credential risk. These are Terraform changes with no application impact.

**Expected risk reduction:** Eliminates direct internet access to database and management ports. Removes the network path that makes credential exposure immediately exploitable.

**Evidence:** `3ba928b4fd97` (CKV_GCP_88, CRITICAL); `dbbdc1cf61c2` (CKV_GCP_2, CRITICAL); `57df84a4027d` (CKV_GCP_3, CRITICAL); `382c6fe86e55` (CKV_GCP_77, HIGH); `e5f32d7b4723` (CKV_GCP_75, HIGH); `be6a83a66fe7` (CKV_GCP_106, MEDIUM)

### Action 5: Pin deployed image references to SHA256 digests and validate cosign verification passes

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

Kyverno confirms the cosign image verification policy fails at runtime because deployed images lack pinned digests. The supply chain signing at build time is ineffective without digest pinning at deploy time. Update CI to write the image digest into manifests/Helm values at build time.

**Expected risk reduction:** Restores supply chain integrity control. Prevents substitution of unsigned images in the live cluster.

**Evidence:** `f84f2db980d4` (verify-image-cosign/verify-cosign-keyless-signature, CRITICAL); `3f6606939177` (verify-image-cosign/autogen-verify-cosign-keyless-signature, CRITICAL); `6a3ccaf023bb` (latest-tag, MEDIUM)

### Action 6: Remediate backend injection vulnerabilities (OS command, path traversal, SQL) and disable Flask debug mode

**Estimated complexity:** HIGH &nbsp;|&nbsp; **Dependencies:** none

SonarCloud (critical BLOCKER) and CodeQL independently confirm OS command injection, path traversal, and SQL injection in the backend. Flask debug mode is confirmed enabled, which turns any unhandled exception into a code execution primitive. These require code changes.

**Expected risk reduction:** Eliminates confirmed remote code execution and data exfiltration vectors in the backend application layer.

**Evidence:** `688d20fa838a` (pythonsecurity:S2076, CRITICAL); `447335a06a0f` (pythonsecurity:S2083, CRITICAL); `6f568715650c` (py/command-line-injection, MEDIUM); `757685f73438` (py/sql-injection, MEDIUM); `9de17c0300aa` (py/path-injection, MEDIUM); `217911839f44` (py/flask-debug, MEDIUM)

### Action 7: Upgrade frontend axios to >=1.16.0 and dompurify to >=3.4.12; also upgrade lodash and moment

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

axios@0.21.1 carries 2 critical and 8+ high CVEs; dompurify@2.3.3 carries 1 critical and multiple high/medium CVEs including XSS bypasses in the XSS sanitizer itself. Both have documented fixed versions. A single upgrade per package resolves all known CVEs. Also upgrade lodash to >=4.18.1 and moment to >=2.29.4.

**Expected risk reduction:** Resolves 50+ frontend dependency CVEs including 3 critical findings. Restores the integrity of the XSS sanitization layer.

**Evidence:** `0dc16d7ed2e9` (SNYK-JS-AXIOS-16298058, CRITICAL); `a7b165255456` (SNYK-JS-AXIOS-16299904, CRITICAL); `82d7f2881d4c` (SNYK-JS-DOMPURIFY-8318045, CRITICAL); `9eda1fcf005c` (SNYK-JS-DOMPURIFY-7984421, HIGH); `6ad0842ac459` (SNYK-JS-LODASH-1040724, HIGH); `69e3a556368e` (SNYK-JS-LODASH-15869625, HIGH); `a6a58d1a71c4` (SNYK-JS-MOMENT-2440688, HIGH); `61c29417af07` (SNYK-JS-MOMENT-2944238, HIGH)

### Action 8: Rebuild backend container image from updated Debian 12 base with patched system packages

**Estimated complexity:** MEDIUM &nbsp;|&nbsp; **Dependencies:** ACT-005

Critical CVEs in openssl, gnutls28, krb5, expat, and zlib are present in the backend container image. These are OS-layer packages requiring a base image rebuild. Patched versions are documented in remediation_notes for each finding.

**Expected risk reduction:** Eliminates critical OS-layer CVEs in TLS and authentication libraries from the live backend container.

**Evidence:** `80c766bd7abd` (SNYK-DEBIAN12-OPENSSL-15969314, CRITICAL); `9aeed721127a` (SNYK-DEBIAN12-GNUTLS28-16344303, CRITICAL); `903cec21ca4e` (SNYK-DEBIAN12-GNUTLS28-16344325, CRITICAL); `971307a2fb61` (SNYK-DEBIAN12-KRB5-7411315, CRITICAL); `083d9d82d66b` (SNYK-DEBIAN12-ZLIB-6008963, CRITICAL); `406f0f4dac9b` (SNYK-DEBIAN12-EXPAT-7855502, CRITICAL); `afabe834cfa4` (SNYK-DEBIAN12-EXPAT-7855503, CRITICAL)

### Action 9: Upgrade backend Python dependencies: pillow to >=12.3.0, cryptography to >=48.0.1, flask-cors to >=6.0.0

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

pillow@11.3.0 carries 16 findings (high/medium) including out-of-bounds writes and memory allocation issues. cryptography@43.0.3 carries 4 findings. flask-cors@4.0.2 carries 4 findings including improper access control. Each has a single upgrade target that resolves all known CVEs for that package.

**Expected risk reduction:** Resolves 24+ backend application-layer dependency CVEs across three packages in three upgrade operations.

**Evidence:** `524835b29043` (SNYK-PYTHON-PILLOW-15265439, HIGH); `8891af27bcb3` (SNYK-PYTHON-PILLOW-16032068, HIGH); `0b2ca1c5c052` (SNYK-PYTHON-PILLOW-16419303, HIGH); `a41f49c22ac4` (SNYK-PYTHON-PILLOW-17824465, HIGH); `574389232a75` (SNYK-PYTHON-CRYPTOGRAPHY-15263096, HIGH); `ca8ca4aa1e13` (SNYK-PYTHON-CRYPTOGRAPHY-17344551, HIGH); `b3a42d493492` (SNYK-PYTHON-FLASKCORS-7707876, HIGH); `d6fc6f9489fe` (SNYK-PYTHON-FLASKCORS-9668954, HIGH)

### Action 10: Enforce public access prevention and access logging on GCS bucket; enable Workload Identity and network hardening

**Estimated complexity:** MEDIUM &nbsp;|&nbsp; **Dependencies:** ACT-003

The public storage bucket, missing access logging, disabled master authorized networks, missing NetworkPolicy, and missing VPC flow logs are all confirmed Terraform gaps. These are lower urgency than the above but represent a meaningful reduction in the infrastructure attack surface and audit capability.

**Expected risk reduction:** Closes the public data exposure risk on the storage bucket. Adds network segmentation and audit visibility to the cluster.

**Evidence:** `189191849e41` (CKV_GCP_114, CRITICAL); `724685b547f7` (CKV_GCP_29, HIGH); `354070e54e2f` (CKV_GCP_62, MEDIUM); `7a97a533c5a2` (CKV_GCP_12, MEDIUM); `0d8acda49a79` (CKV_GCP_20, MEDIUM); `8d32bd1d8e72` (CKV_GCP_61, MEDIUM); `6cb8ab1f3f5f` (CKV_GCP_66, MEDIUM)

---

## Release Readiness Assessment

**Confidence:** HIGH

This release has multiple independent, high-confidence blocking conditions across every measured domain. In the live cluster: privilege escalation is not blocked, containers run as root, no seccomp profiles are set, and cosign image verification fails at runtime — all confirmed by Kyverno policy enforcement. In the application layer: OS command injection, path traversal, SQL injection, and XSS are confirmed at critical severity by two independent tools (SonarCloud BLOCKER + CodeQL). Hardcoded PostgreSQL credentials are confirmed by three independent tools. In infrastructure: Owner-level IAM is granted at project scope, Workload Identity is disabled, and unrestricted firewall rules expose SSH, RDP, and MySQL to the internet. The combination of these findings creates a confirmed path from a single container-level exploit to full GCP project compromise. No single finding in isolation would necessarily block deployment, but the convergence of critical application vulnerabilities, absent runtime security controls, excessive IAM, and open network perimeter makes this release unsafe for production deployment in its current state.

**Blocking evidence:** `f913039e3a2a` (disallow-privilege-escalation/privilege-escalation, CRITICAL); `73e307bc47c2` (disallow-privilege-escalation/autogen-privilege-escalation, CRITICAL); `688d20fa838a` (pythonsecurity:S2076, CRITICAL); `447335a06a0f` (pythonsecurity:S2083, CRITICAL); `049991827bea` (secrets:S6698, CRITICAL); `f84f2db980d4` (verify-image-cosign/verify-cosign-keyless-signature, CRITICAL); `3f6606939177` (verify-image-cosign/autogen-verify-cosign-keyless-signature, CRITICAL); `54c214b711d1` (CKV_GCP_49, CRITICAL); `0487801b1fb6` (CKV_GCP_117, CRITICAL); `f1f751c2ee51` (CKV_GCP_69, HIGH); `3ba928b4fd97` (CKV_GCP_88, CRITICAL); `dbbdc1cf61c2` (CKV_GCP_2, CRITICAL); `57df84a4027d` (CKV_GCP_3, CRITICAL)

**Conditions:**
- allowPrivilegeEscalation=false and runAsNonRoot=true enforced on all deployed workloads (Kyverno policy must pass)
- All hardcoded credentials rotated and removed from source; secrets loaded from a secret manager at runtime
- Backend OS command injection, path traversal, and SQL injection vulnerabilities remediated in code
- Flask debug mode disabled via environment configuration
- Deployed image references pinned to SHA256 digests and cosign verification policy passing in the live cluster
- Workload Identity enabled on the GKE node pool and Owner IAM binding replaced with a least-privilege role
- Unrestricted firewall rules (SSH, RDP, MySQL, FTP) restricted to specific source CIDRs
- Frontend axios upgraded to >=1.16.0 and dompurify upgraded to >=3.4.12 (resolves critical CVEs in the XSS sanitizer)

---

## Assumptions & Unknowns

- **`signal_availability.reachability`** = `"not_collected"` — Reachability is not collected. All vulnerability prioritization is based on severity and confidence alone. Some high/medium findings may not be reachable in practice, which could lower their effective priority. Conversely, critical findings (especially injection and XSS) are assumed reachable given the application accepts user input — but this is an inference, not a measured fact. The absence of reachability data means the report cannot distinguish between a vulnerability in a dead code path and one in a hot path.
- **`signal_availability.exploitability`** = `"not_collected"` — Exploitability is not collected. The report cannot distinguish between a vulnerability that requires authentication, specific preconditions, or local access versus one that is trivially exploitable from the internet. This gap most significantly affects the OS-layer container CVEs, where exploitability varies widely by CVE. The critical/high severity ratings are used as the best available proxy.
- **`signal_availability.internet_exposure`** = `"not_collected"` — Internet exposure is not collected. The report cannot confirm which services are actually internet-facing. The open firewall rules (0.0.0.0/0) suggest broad exposure, but the actual routing and load balancer configuration is not measured. This gap means the network-level risk assessment is based on infrastructure configuration findings rather than confirmed traffic paths.
- **`signal_availability.delta_status`** = `"not_collected"` — Delta status is not collected. The report cannot distinguish between findings that are new in this release versus findings that have been present and accepted in prior releases. This means all findings are treated as equally urgent, which may overstate the incremental risk introduced by this specific release while understating the accumulated technical debt.
- **`provenance.application_security`** = `{"per_workflow": {"backend-ci.yaml": {"source_version": "2382597af3ea184f9897d9373f10bc0b59ff083d", "exact_match": true}, "frontend-ci.yaml": {"source_version": "2382597af3ea184f9897d9373f10bc0b59ff083d", "exact_match": true}, "app-security-scan-backend.yaml": {"source_version": "2382597af3ea184f9897d9373f10bc0b59ff083d", "exact_match": true}, "app-security-scan-frontend.yaml": {"source_version": "2382597af3ea184f9897d9373f10bc0b59ff083d", "exact_match": true}}, "any_used_fallback_commit": false, "note": "Per-workflow real source commit, since backend-ci.yaml/frontend-ci.yaml/app-security-scan-*.yaml only re-run on backend/**/frontend/** changes \u2014 exact_match: false means that workflow's latest successful run came from a different commit than this release, surfaced here rather than silently assumed current. Still file-level only within each workflow \u2014 no per-tool (codeql vs sonarcloud vs gitguardian vs snyk) timestamps exist yet."}` — Per-tool timestamps within each workflow are not tracked — only file-level workflow timestamps exist. It is not possible to determine whether codeql, sonarcloud, gitguardian, or snyk results within a given workflow run are from the same scan invocation or from cached/prior results. This limits confidence that all application security findings reflect the exact state of this release commit.
- **`supply_chain.backend.verification_status`** = `"SUCCESS"` — The supply_chain block reports SUCCESS for both backend and frontend image verification. However, Kyverno's live policy check (finding f84f2db980d4 and 3f6606939177) reports missing digests for the deployed image references. This discrepancy means the build-time verification status does not reflect the runtime enforcement state. The supply chain control should be treated as non-functional until the Kyverno policy passes in the live cluster.
- **`sbom_summary.backend.packages_with_known_vulnerabilities`** = `["apt@2.6.1", "coreutils@9.1-1", "diffutils@1:3.8-4", "dpkg@1.21.22", "gzip@1.12-1", "libcap2@1:2.66-4", "libgcrypt20@1.10.1-3", "libtasn1-6@4.19.0-2", "openssl@3.0.9-1", "sed@4.9-1", "tar@1.34+dfsg-1.2"]` — The SBOM lists packages with known vulnerabilities (apt, coreutils, dpkg, gzip, tar, sed, etc.) that do not appear as individual findings in the findings array. It is not clear whether these were scanned and found clean, scanned and suppressed, or not scanned at the finding level. If these packages carry unscanned vulnerabilities, the container security risk is understated.
- **`scan_status.backend.snyk`** = `"SUCCESS"` — Snyk reports both application-layer (pip) and OS-layer (deb) findings for the backend. Several OS-layer findings (zlib, expat high severity) lack remediation_notes with fixed-in versions, suggesting no fix may be available in the current Debian 12 package stream. If fixes are not available, a time-boxed exception policy and compensating controls (network isolation, WAF) would be needed rather than a simple package upgrade.
- **`provenance.infrastructure_security.commits_behind`** = _[pointer did not resolve against final_release_context.json]_ — commits_behind is null because versions match between application_security and infrastructure_security. This is the expected case per the provenance note. No staleness concern applies to infrastructure findings for this release.
- **`signal_availability.business_impact`** = `"not_collected"` — Business impact is not collected. The report cannot weight findings by the business criticality of the affected component or data. All components (backend, frontend, deployed-app, infrastructure, terraform) are treated as equally business-critical. If some components are non-production or handle non-sensitive data, the effective risk of their findings may be lower than assessed here.

---

## Final Recommendation

### ❌ DO NOT APPROVE

This release has multiple independent, high-confidence blocking conditions across every measured domain. In the live cluster: privilege escalation is not blocked, containers run as root, no seccomp profiles are set, and cosign image verification fails at runtime — all confirmed by Kyverno policy enforcement. In the application layer: OS command injection, path traversal, SQL injection, and XSS are confirmed at critical severity by two independent tools (SonarCloud BLOCKER + CodeQL). Hardcoded PostgreSQL credentials are confirmed by three independent tools. In infrastructure: Owner-level IAM is granted at project scope, Workload Identity is disabled, and unrestricted firewall rules expose SSH, RDP, and MySQL to the internet. The combination of these findings creates a confirmed path from a single container-level exploit to full GCP project compromise. No single finding in isolation would necessarily block deployment, but the convergence of critical application vulnerabilities, absent runtime security controls, excessive IAM, and open network perimeter makes this release unsafe for production deployment in its current state.
