# Release Intelligence Report

**Repository:** `ravisinghrajput95/AI-Powered-DevSecOps-CI-CD-Pipeline`
**Release Version:** `0b5819aa43fc5fcfbb55815439528f0a3ca3eeeb`
**Report Generated:** 2026-07-25T12:46:49.328011+00:00
**Report ID:** `2972549035486c62`
**Components Assessed:** backend, frontend, deployed-app, infrastructure, terraform

---

## Executive Summary

**Overall Health:** CRITICAL &nbsp;|&nbsp; **Deployment Confidence:** LOW

**Dominant Risk Themes:** Privilege escalation enabled across deployed workloads, Critical injection and secret-exposure in backend code, Severely outdated frontend dependencies (axios, dompurify, lodash), Open firewall rules and excessive IAM on GCP infrastructure, Container images unsigned and unverifiable at deploy time, Critical OS-layer CVEs in deployed backend container

This release presents a CRITICAL security posture across all five measured domains. The backend exposes OS-command injection, path traversal (4 occurrences), XSS, and hardcoded PostgreSQL credentials — all rated BLOCKER by SonarCloud with high confidence. The frontend ships axios@0.21.1 and dompurify@2.3.3, packages carrying 28 and 20 CVEs respectively, including critical HTTP Response Splitting and Prototype Pollution. At runtime, Kyverno confirms that deployed workloads allow privilege escalation across 25+ pod locations and run as root without seccomp profiles — these are live, confirmed policy violations on the deployed cluster, not theoretical. The GCP Terraform configuration exposes unrestricted SSH, RDP, and MySQL firewall ingress, grants compute Owner-level IAM at project scope, and has a publicly accessible storage bucket — any one of these would be a standalone blocker. The backend container image carries critical CVEs in openssl, gnutls28, krb5, and expat at the OS layer. Supply chain verification for both images returned UNKNOWN (manifest not found for this release commit), meaning neither image's provenance can be confirmed. The combination of live privilege-escalation violations, critical application-layer injection flaws, infrastructure with open firewall rules and excessive IAM, and unverifiable image supply chain makes this release unsuitable for production deployment without remediation of the blocking items identified below.

---

## Cross-Domain Analysis

### Workload Identity disabled + excessive IAM = node-level project compromise path

**Affected domains:** application_security, infrastructure_security, runtime_security &nbsp;|&nbsp; **Confidence:** HIGH

Terraform disables GKE Workload Identity (GKE Metadata Server not enabled), meaning pods inherit the node's Compute Engine service account. That same service account is granted the compute Owner basic role at project level. A container escape or SSRF from any pod — both of which are evidenced in the application layer — could allow an attacker to reach the metadata server and obtain a token with project-Owner privileges.

**Business impact:** Full GCP project compromise from a single container escape or SSRF exploit. All project resources, data, and other services would be at risk.

**Recommended action:** Enable GKE Workload Identity (set workload_metadata_config.mode = GKE_METADATA) and replace the compute Owner IAM binding with the minimum required predefined role before deploying. Simultaneously remediate SSRF findings in the backend.

**Evidence:** `f1f751c2ee51` (CKV_GCP_69, HIGH); `0487801b1fb6` (CKV_GCP_117, CRITICAL); `54c214b711d1` (CKV_GCP_49, CRITICAL); `ff32e3378a60` (py/full-ssrf, MEDIUM); `37c28065d914` (pythonsecurity:S5144, MEDIUM)

### Unsigned images + runtime image-verification failures = unverifiable workload provenance

**Affected domains:** supply_chain, runtime_security, container_security &nbsp;|&nbsp; **Confidence:** HIGH

Supply chain verification for both backend and frontend images returned UNKNOWN (manifest not found for the release commit). Kyverno's verify-image-cosign policy independently confirms at runtime that the frontend image is missing a cosign digest and that signature verification is being denied due to IAM permissions. This means neither image's build provenance can be confirmed, and the runtime policy enforcement is also broken.

**Business impact:** No assurance that what is running in the cluster was built from the expected source commit. Tampered or substituted images cannot be detected.

**Recommended action:** Fix the Artifact Registry IAM permissions so the Kyverno admission controller can pull image manifests for verification. Ensure the cosign signing step in CI runs and succeeds for every image before deployment. Confirm the release commit tag is pushed to the registry.

**Evidence:** `f84f2db980d4` (verify-image-cosign/verify-cosign-keyless-signature, CRITICAL); `3f6606939177` (verify-image-cosign/autogen-verify-cosign-keyless-signature, CRITICAL)

### Backend injection + debug mode + stack trace exposure = direct code execution risk

**Affected domains:** application_security, runtime_security &nbsp;|&nbsp; **Confidence:** HIGH

The backend has confirmed OS-command injection from user-controlled data (SonarCloud BLOCKER), SQL injection (CodeQL), and path traversal (4 occurrences, both SonarCloud and CodeQL). Flask debug mode is enabled (CodeQL + SonarCloud), which exposes an interactive debugger. Stack traces are confirmed to flow to external users (CodeQL, 3 occurrences). These findings compound: an attacker who triggers an error gets a stack trace, can use the debug console, and has multiple injection vectors to execute arbitrary OS commands.

**Business impact:** Remote code execution on the backend container, with potential for lateral movement to the database (hardcoded credentials also present) and the cluster.

**Recommended action:** Disable Flask debug mode immediately for any production-facing deployment. Remediate injection vectors using parameterized queries and input validation. Suppress stack traces from HTTP responses.

**Evidence:** `688d20fa838a` (pythonsecurity:S2076, CRITICAL); `6f568715650c` (py/command-line-injection, MEDIUM); `757685f73438` (py/sql-injection, MEDIUM); `447335a06a0f` (pythonsecurity:S2083, CRITICAL); `9de17c0300aa` (py/path-injection, MEDIUM); `217911839f44` (py/flask-debug, MEDIUM); `0c9c83aacaa9` (docker:S4507, LOW); `c504da4d8155` (py/stack-trace-exposure, MEDIUM)

### Hardcoded credentials in source + secret-exposure findings = credential compromise

**Affected domains:** application_security, supply_chain &nbsp;|&nbsp; **Confidence:** HIGH

SonarCloud reports hardcoded PostgreSQL passwords (4 occurrences, BLOCKER) and a hardcoded SECRET_KEY. GitGuardian independently confirms generic passwords and username/password pairs in both backend and frontend (medium confidence, no_checker validity). These are cross-tool confirmations of the same root cause: credentials committed to source control.

**Business impact:** Database and application credentials are exposed to anyone with repository read access. Rotation is required even after removal from code.

**Recommended action:** Immediately rotate all exposed credentials. Remove them from source control history (git filter-repo or BFG). Load secrets from a secret manager (e.g. GCP Secret Manager) at runtime.

**Evidence:** `049991827bea` (secrets:S6698, CRITICAL); `ba3dc970c4bd` (python:S2068, MEDIUM); `45577584570d` (Generic Password, MEDIUM); `00af2baa5ff3` (Username Password, MEDIUM); `878a66ae7816` (Username Password, MEDIUM); `0ad3628d28ea` (Generic Password, MEDIUM)

### Open firewall rules + missing cluster network hardening = broad network attack surface

**Affected domains:** infrastructure_security, runtime_security &nbsp;|&nbsp; **Confidence:** HIGH

Terraform provisions a firewall rule (google_compute_firewall.allow_all) that permits unrestricted SSH, RDP, MySQL, and FTP ingress from 0.0.0.0/0. Simultaneously, the GKE cluster lacks master authorized networks, alias IP ranges, VPC flow logs, and network policy. This means both the GCP compute layer and the Kubernetes network layer are fully open, with no visibility into traffic flows.

**Business impact:** Any internet-connected host can attempt to reach SSH, RDP, and database ports directly. Lateral movement within the cluster is unconstrained.

**Recommended action:** Restrict all firewall rules to specific source CIDRs and required ports only. Enable master authorized networks, alias IP ranges, VPC flow logs, and Kubernetes NetworkPolicy on the GKE cluster.

**Evidence:** `57df84a4027d` (CKV_GCP_3, CRITICAL); `dbbdc1cf61c2` (CKV_GCP_2, CRITICAL); `3ba928b4fd97` (CKV_GCP_88, CRITICAL); `382c6fe86e55` (CKV_GCP_77, HIGH); `e5f32d7b4723` (CKV_GCP_75, HIGH); `53953124a35c` (CKV_GCP_23, MEDIUM); `0d8acda49a79` (CKV_GCP_20, MEDIUM); `8d32bd1d8e72` (CKV_GCP_61, MEDIUM); `7a97a533c5a2` (CKV_GCP_12, MEDIUM)

### One axios upgrade resolves 28 frontend CVEs across critical and high severity

**Affected domains:** application_security, container_security &nbsp;|&nbsp; **Confidence:** HIGH

All 28 axios CVEs (critical and high) trace to a single package version: axios@0.21.1. The highest-severity fixes require upgrading to 0.32.0 or 1.16.0. This is a single dependency upgrade that resolves the entire axios CVE surface, including HTTP Response Splitting, Prototype Pollution, SSRF, CSRF, and ReDoS.

**Business impact:** A single npm upgrade eliminates the largest single source of critical/high CVEs in the frontend, reducing the frontend's vulnerable dependency count significantly.

**Recommended action:** Upgrade axios to >=1.16.0 (or >=0.32.0 if staying on the 0.x line) in the frontend package.json and regenerate the lock file.

**Evidence:** `0dc16d7ed2e9` (SNYK-JS-AXIOS-16298058, CRITICAL); `a7b165255456` (SNYK-JS-AXIOS-16299904, CRITICAL); `472ae7a3640e` (SNYK-JS-AXIOS-15252993, HIGH); `301f4d9e8a0f` (SNYK-JS-AXIOS-1579269, HIGH); `afac6e0ca60a` (SNYK-JS-AXIOS-15969258, HIGH); `94e792fcb5eb` (SNYK-JS-AXIOS-16299923, HIGH); `56809903bbcf` (SNYK-JS-AXIOS-17111060, HIGH); `21c208e62117` (SNYK-JS-AXIOS-17111062, HIGH); `4cf7569f2736` (SNYK-JS-AXIOS-17111079, HIGH); `057a515cfb47` (SNYK-JS-AXIOS-17172681, HIGH); `d05779733c13` (SNYK-JS-AXIOS-6032459, HIGH)

### Container OS-layer CVEs in backend image compound application-layer risk

**Affected domains:** container_security, application_security, runtime_security &nbsp;|&nbsp; **Confidence:** MEDIUM

The backend container image carries critical CVEs in openssl, gnutls28, krb5, expat, and zlib at the Debian OS layer, alongside high-severity CVEs in glibc, pam, systemd, and perl. These are the same container that runs the backend application with confirmed injection and debug-mode vulnerabilities. A successful application exploit lands in a container with a critically vulnerable OS layer, increasing post-exploitation capability.

**Business impact:** Post-exploitation privilege escalation or lateral movement is easier when the container OS itself has unpatched critical vulnerabilities.

**Recommended action:** Rebuild the backend container from a current Debian base image (or use a distroless/minimal base) to pick up OS-level security patches. Automate base image updates in CI.

**Evidence:** `80c766bd7abd` (SNYK-DEBIAN12-OPENSSL-15969314, CRITICAL); `9aeed721127a` (SNYK-DEBIAN12-GNUTLS28-16344303, CRITICAL); `903cec21ca4e` (SNYK-DEBIAN12-GNUTLS28-16344325, CRITICAL); `971307a2fb61` (SNYK-DEBIAN12-KRB5-7411315, CRITICAL); `083d9d82d66b` (SNYK-DEBIAN12-ZLIB-6008963, CRITICAL); `406f0f4dac9b` (SNYK-DEBIAN12-EXPAT-7855502, CRITICAL); `afabe834cfa4` (SNYK-DEBIAN12-EXPAT-7855503, CRITICAL)

---

## Top Risks

### Risk 1: Live privilege escalation across deployed workloads (Kyverno confirmed)

**Confidence:** HIGH

**Impact:** Any process in any affected container can escalate to root-equivalent privileges. Combined with the backend's confirmed OS-command injection, this is a direct path to full container and potentially node compromise on the live cluster.

**Why it matters:** This is not a configuration drift finding — Kyverno confirmed this violation at admission time against the currently deployed workloads. The 25-location autogen finding indicates the issue spans Deployments/StatefulSets cluster-wide, not a single pod.

**Recommended action:** Set allowPrivilegeEscalation: false in the securityContext of all containers and initContainers across all affected workloads. This is a one-line fix per container spec; prioritize backend and frontend Deployments first.

**Evidence:** `f913039e3a2a` (disallow-privilege-escalation/privilege-escalation, CRITICAL); `73e307bc47c2` (disallow-privilege-escalation/autogen-privilege-escalation, CRITICAL)

### Risk 2: Backend OS-command injection and path traversal from user-controlled input

**Confidence:** HIGH

**Impact:** An unauthenticated attacker can execute arbitrary OS commands and traverse the filesystem on the backend container. With debug mode enabled and stack traces exposed, the attack surface is further widened.

**Why it matters:** SonarCloud rated these BLOCKER with high confidence. CodeQL independently confirms command-line injection and path injection. Multiple tools confirming the same root cause significantly raises the probability these are true positives.

**Recommended action:** Immediately audit and remediate all code paths that construct OS commands or file paths from user input. Use subprocess with argument lists (not shell=True), and validate/canonicalize paths against an allowlist base directory. Disable Flask debug mode.

**Evidence:** `688d20fa838a` (pythonsecurity:S2076, CRITICAL); `447335a06a0f` (pythonsecurity:S2083, CRITICAL); `6f568715650c` (py/command-line-injection, MEDIUM); `9de17c0300aa` (py/path-injection, MEDIUM); `217911839f44` (py/flask-debug, MEDIUM); `c504da4d8155` (py/stack-trace-exposure, MEDIUM)

### Risk 3: Hardcoded PostgreSQL credentials and SECRET_KEY in source code

**Confidence:** HIGH

**Impact:** Database credentials and the application's cryptographic signing key are exposed to anyone with repository read access. The database is directly reachable via the open MySQL firewall rule, making credential use trivial.

**Why it matters:** SonarCloud flagged this as BLOCKER (4 occurrences). GitGuardian independently detected generic passwords and username/password pairs. The open firewall rule (RISK-005) means these credentials can be used directly from the internet.

**Recommended action:** Rotate all exposed credentials immediately. Remove from source history. Migrate to GCP Secret Manager with runtime injection via environment variables or mounted secrets.

**Evidence:** `049991827bea` (secrets:S6698, CRITICAL); `ba3dc970c4bd` (python:S2068, MEDIUM); `45577584570d` (Generic Password, MEDIUM); `00af2baa5ff3` (Username Password, MEDIUM)

### Risk 4: GCP infrastructure: open firewall to internet + project-Owner IAM + public storage bucket

**Confidence:** HIGH

**Impact:** SSH, RDP, MySQL, and FTP ports are reachable from any internet host. The Compute Engine service account has project-Owner IAM. A public storage bucket may expose sensitive assets. Together these represent a trivially exploitable infrastructure posture.

**Why it matters:** These are Checkov findings with high confidence against the Terraform that provisions the live GCP environment. The firewall rule is named allow_all, suggesting intentional broad access rather than accidental misconfiguration.

**Recommended action:** Restrict firewall source_ranges to specific CIDRs. Replace the Owner IAM binding with the minimum required role. Enable public access prevention on the storage bucket. Apply and plan Terraform changes before next deployment.

**Evidence:** `57df84a4027d` (CKV_GCP_3, CRITICAL); `dbbdc1cf61c2` (CKV_GCP_2, CRITICAL); `3ba928b4fd97` (CKV_GCP_88, CRITICAL); `0487801b1fb6` (CKV_GCP_117, CRITICAL); `54c214b711d1` (CKV_GCP_49, CRITICAL); `189191849e41` (CKV_GCP_114, CRITICAL)

### Risk 5: Container image supply chain unverifiable for this release

**Confidence:** HIGH

**Impact:** Neither the backend nor frontend image can be confirmed as built from the expected source commit. Kyverno's cosign verification is also failing due to IAM permission errors, meaning the runtime admission control that should catch tampered images is non-functional.

**Why it matters:** supply_chain.verification_status is UNKNOWN for both images. The Kyverno runtime findings confirm the verification failure is live, not just a pre-deploy check gap. Without this control, there is no assurance about what code is actually running.

**Recommended action:** Fix Artifact Registry IAM so the Kyverno service account can pull manifests. Ensure cosign signing runs in CI for every image build. Confirm the release commit image tag exists in the registry before deploying.

**Evidence:** `f84f2db980d4` (verify-image-cosign/verify-cosign-keyless-signature, CRITICAL); `3f6606939177` (verify-image-cosign/autogen-verify-cosign-keyless-signature, CRITICAL)

### Risk 6: Frontend axios@0.21.1: 28 CVEs including critical HTTP Response Splitting and Prototype Pollution

**Confidence:** HIGH

**Impact:** The frontend ships a severely outdated HTTP client with a large CVE surface spanning response splitting, prototype pollution, SSRF, CSRF, and ReDoS. Critical-severity CVEs are present.

**Why it matters:** A single package upgrade to axios>=1.16.0 resolves all 28 CVEs. The current version is more than 3 major patch series behind the fix point for the most severe issues.

**Recommended action:** Upgrade axios to >=1.16.0 in frontend/package.json. Regenerate package-lock.json and run the full test suite.

**Evidence:** `0dc16d7ed2e9` (SNYK-JS-AXIOS-16298058, CRITICAL); `a7b165255456` (SNYK-JS-AXIOS-16299904, CRITICAL); `472ae7a3640e` (SNYK-JS-AXIOS-15252993, HIGH); `301f4d9e8a0f` (SNYK-JS-AXIOS-1579269, HIGH); `afac6e0ca60a` (SNYK-JS-AXIOS-15969258, HIGH); `21c208e62117` (SNYK-JS-AXIOS-17111062, HIGH)

### Risk 7: Backend container OS layer: critical CVEs in openssl, gnutls28, krb5, expat, zlib

**Confidence:** HIGH

**Impact:** The backend container image runs with critically vulnerable cryptographic and parsing libraries at the OS layer. These are reachable by any code running in the container, including via the confirmed injection vulnerabilities.

**Why it matters:** Multiple critical-severity Debian package CVEs (openssl, gnutls28, krb5, expat, zlib) are present in the deployed backend image. Rebuilding from a current base image resolves all of them in a single operation.

**Recommended action:** Rebuild the backend container from a current Debian 12 base image (or switch to a distroless/minimal base). Automate base image refresh in CI on a regular cadence.

**Evidence:** `80c766bd7abd` (SNYK-DEBIAN12-OPENSSL-15969314, CRITICAL); `9aeed721127a` (SNYK-DEBIAN12-GNUTLS28-16344303, CRITICAL); `903cec21ca4e` (SNYK-DEBIAN12-GNUTLS28-16344325, CRITICAL); `971307a2fb61` (SNYK-DEBIAN12-KRB5-7411315, CRITICAL); `083d9d82d66b` (SNYK-DEBIAN12-ZLIB-6008963, CRITICAL); `406f0f4dac9b` (SNYK-DEBIAN12-EXPAT-7855502, CRITICAL); `afabe834cfa4` (SNYK-DEBIAN12-EXPAT-7855503, CRITICAL)

### Risk 8: Workload Identity disabled: pods inherit node SA with project-Owner IAM

**Confidence:** HIGH

**Impact:** Without Workload Identity, every pod on the cluster can reach the GCE metadata server and obtain a token for the node's service account, which holds project-Owner IAM. This is a direct privilege escalation path from any container to full GCP project control.

**Why it matters:** This is the intersection of CORR-001: the infrastructure misconfiguration (disabled Workload Identity) and the excessive IAM grant (Owner role) combine to create a single-hop path from container to project compromise.

**Recommended action:** Enable GKE Workload Identity on the cluster and node pool. Replace the project-level Owner IAM binding with the minimum required predefined role scoped to the specific resource.

**Evidence:** `f1f751c2ee51` (CKV_GCP_69, HIGH); `0487801b1fb6` (CKV_GCP_117, CRITICAL); `54c214b711d1` (CKV_GCP_49, CRITICAL)

---

## Highest Priority Actions

### Action 1: Set allowPrivilegeEscalation: false on all deployed container specs

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

Kyverno confirmed this violation is live across 25+ pod locations. This is a one-line securityContext change per container that immediately satisfies the Kyverno policy and removes the privilege escalation path from all running workloads.

**Expected risk reduction:** Eliminates confirmed live privilege escalation across all affected workloads. Resolves RISK-001 and the Kyverno critical findings.

**Evidence:** `f913039e3a2a` (disallow-privilege-escalation/privilege-escalation, CRITICAL); `73e307bc47c2` (disallow-privilege-escalation/autogen-privilege-escalation, CRITICAL)

### Action 2: Disable Flask debug mode and suppress stack traces from HTTP responses

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

Flask debug mode exposes an interactive debugger to anyone who can trigger an error. Stack traces are confirmed to flow to external users. Both are independently confirmed by CodeQL and SonarCloud. This is a configuration change with immediate impact on the blast radius of the injection vulnerabilities.

**Expected risk reduction:** Removes the interactive debugger attack surface and eliminates information leakage that aids exploitation of injection vulnerabilities.

**Evidence:** `217911839f44` (py/flask-debug, MEDIUM); `0c9c83aacaa9` (docker:S4507, LOW); `c504da4d8155` (py/stack-trace-exposure, MEDIUM)

### Action 3: Rotate all exposed credentials and migrate to GCP Secret Manager

**Estimated complexity:** MEDIUM &nbsp;|&nbsp; **Dependencies:** none

PostgreSQL passwords and SECRET_KEY are confirmed hardcoded in source (SonarCloud BLOCKER + GitGuardian). The open MySQL firewall rule means these credentials are directly usable from the internet. Rotation must happen before any other remediation is meaningful.

**Expected risk reduction:** Eliminates the immediate credential compromise risk. Resolves RISK-003 and removes the most direct path to database access.

**Evidence:** `049991827bea` (secrets:S6698, CRITICAL); `ba3dc970c4bd` (python:S2068, MEDIUM); `45577584570d` (Generic Password, MEDIUM); `00af2baa5ff3` (Username Password, MEDIUM)

### Action 4: Restrict GCP firewall rules and replace project-Owner IAM with minimum required role

**Estimated complexity:** MEDIUM &nbsp;|&nbsp; **Dependencies:** ACT-003

The allow_all firewall rule exposes SSH, RDP, MySQL, and FTP to the internet. The project-Owner IAM binding on the Compute Engine SA means any node compromise yields full project access. These are Terraform changes that must be applied before the infrastructure is safe to operate.

**Expected risk reduction:** Eliminates direct internet access to sensitive ports and removes the project-Owner privilege escalation path. Resolves RISK-004 and partially resolves RISK-008.

**Evidence:** `57df84a4027d` (CKV_GCP_3, CRITICAL); `dbbdc1cf61c2` (CKV_GCP_2, CRITICAL); `3ba928b4fd97` (CKV_GCP_88, CRITICAL); `0487801b1fb6` (CKV_GCP_117, CRITICAL); `54c214b711d1` (CKV_GCP_49, CRITICAL); `189191849e41` (CKV_GCP_114, CRITICAL)

### Action 5: Enable GKE Workload Identity on cluster and node pool

**Estimated complexity:** MEDIUM &nbsp;|&nbsp; **Dependencies:** ACT-004

Without Workload Identity, pods inherit the node SA's project-Owner token via the metadata server. Enabling Workload Identity severs this path and is a prerequisite for safe operation of any workload on this cluster.

**Expected risk reduction:** Eliminates the metadata-server-based privilege escalation path from pods to project-Owner. Resolves RISK-008 and CORR-001.

**Evidence:** `f1f751c2ee51` (CKV_GCP_69, HIGH); `0487801b1fb6` (CKV_GCP_117, CRITICAL); `54c214b711d1` (CKV_GCP_49, CRITICAL)

### Action 6: Remediate backend OS-command injection, SQL injection, and path traversal

**Estimated complexity:** HIGH &nbsp;|&nbsp; **Dependencies:** ACT-002

SonarCloud (BLOCKER) and CodeQL independently confirm injection and path traversal vulnerabilities in the backend. These are the highest-severity application code findings and represent direct remote code execution risk.

**Expected risk reduction:** Eliminates the primary remote code execution vectors in the backend. Resolves RISK-002 and CORR-003.

**Evidence:** `688d20fa838a` (pythonsecurity:S2076, CRITICAL); `447335a06a0f` (pythonsecurity:S2083, CRITICAL); `6f568715650c` (py/command-line-injection, MEDIUM); `9de17c0300aa` (py/path-injection, MEDIUM); `757685f73438` (py/sql-injection, MEDIUM)

### Action 7: Fix Artifact Registry IAM and ensure cosign signing runs in CI for all images

**Estimated complexity:** MEDIUM &nbsp;|&nbsp; **Dependencies:** ACT-004

Both image supply chain verifications returned UNKNOWN. Kyverno's runtime cosign check is failing due to IAM permission denial. Until this is fixed, there is no assurance about what code is running in the cluster.

**Expected risk reduction:** Restores supply chain integrity verification. Resolves RISK-005 and CORR-002.

**Evidence:** `f84f2db980d4` (verify-image-cosign/verify-cosign-keyless-signature, CRITICAL); `3f6606939177` (verify-image-cosign/autogen-verify-cosign-keyless-signature, CRITICAL)

### Action 8: Upgrade frontend axios to >=1.16.0 and dompurify to >=3.4.12

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

axios@0.21.1 carries 28 CVEs (2 critical). dompurify@2.3.3 carries 20 CVEs (1 critical). Both have clear fix versions available. A single upgrade per package resolves the entire CVE surface for each.

**Expected risk reduction:** Eliminates 48 CVEs across two packages, including 3 critical-severity findings. Resolves RISK-006 and CORR-006.

**Evidence:** `0dc16d7ed2e9` (SNYK-JS-AXIOS-16298058, CRITICAL); `a7b165255456` (SNYK-JS-AXIOS-16299904, CRITICAL); `82d7f2881d4c` (SNYK-JS-DOMPURIFY-8318045, CRITICAL); `472ae7a3640e` (SNYK-JS-AXIOS-15252993, HIGH); `9eda1fcf005c` (SNYK-JS-DOMPURIFY-7984421, HIGH)

### Action 9: Rebuild backend container from current Debian 12 base image

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** ACT-007

The backend container carries critical OS-layer CVEs in openssl, gnutls28, krb5, expat, and zlib. Rebuilding from a current base image resolves all of these in a single operation and is the standard remediation for OS-layer container CVEs.

**Expected risk reduction:** Eliminates all critical and most high OS-layer CVEs in the backend container. Resolves RISK-007 and CORR-007.

**Evidence:** `80c766bd7abd` (SNYK-DEBIAN12-OPENSSL-15969314, CRITICAL); `9aeed721127a` (SNYK-DEBIAN12-GNUTLS28-16344303, CRITICAL); `903cec21ca4e` (SNYK-DEBIAN12-GNUTLS28-16344325, CRITICAL); `971307a2fb61` (SNYK-DEBIAN12-KRB5-7411315, CRITICAL); `083d9d82d66b` (SNYK-DEBIAN12-ZLIB-6008963, CRITICAL)

### Action 10: Harden deployed workload security contexts: drop ALL capabilities, set seccomp, runAsNonRoot

**Estimated complexity:** MEDIUM &nbsp;|&nbsp; **Dependencies:** ACT-001

Kyverno confirms containers do not drop ALL capabilities, lack seccomp profiles, and run as root. These are live policy violations across 25+ pod locations. Addressing them together (they are all securityContext fields) reduces the post-exploitation capability of any compromised container.

**Expected risk reduction:** Resolves excessive-capabilities, missing-seccomp-profile, and run-as-root runtime findings. Significantly reduces post-exploitation capability.

**Evidence:** `e9fffb850fa8` (disallow-capabilities-strict/require-drop-all, HIGH); `448a793445e1` (disallow-capabilities-strict/autogen-require-drop-all, HIGH); `1a438da1f2bb` (restrict-seccomp-strict/check-seccomp-strict, HIGH); `b5041d14c6bd` (restrict-seccomp-strict/autogen-check-seccomp-strict, HIGH); `55a0910c0cd3` (require-run-as-nonroot/run-as-non-root, HIGH); `79abedf3ae77` (require-run-as-nonroot/autogen-run-as-non-root, HIGH); `a37e4f16b0ef` (run-as-non-root, HIGH)

### Action 11: Upgrade backend Python dependencies: pillow to >=12.3.0, cryptography to >=48.0.1, flask-cors to >=6.0.0

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

pillow@11.3.0 carries 16 CVEs (all high), cryptography@43.0.3 carries 4 CVEs (2 high, 2 medium), and flask-cors@4.0.2 carries 4 CVEs (2 high, 2 medium). All have clear fix versions. A single upgrade per package resolves the full CVE surface.

**Expected risk reduction:** Eliminates 24 application-layer CVEs in the backend Python dependencies.

**Evidence:** `524835b29043` (SNYK-PYTHON-PILLOW-15265439, HIGH); `8891af27bcb3` (SNYK-PYTHON-PILLOW-16032068, HIGH); `0b2ca1c5c052` (SNYK-PYTHON-PILLOW-16419303, HIGH); `574389232a75` (SNYK-PYTHON-CRYPTOGRAPHY-15263096, HIGH); `ca8ca4aa1e13` (SNYK-PYTHON-CRYPTOGRAPHY-17344551, HIGH); `b3a42d493492` (SNYK-PYTHON-FLASKCORS-7707876, HIGH); `d6fc6f9489fe` (SNYK-PYTHON-FLASKCORS-9668954, HIGH)

### Action 12: Add explicit permissions blocks to all GitHub Actions workflows

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

CodeQL found 12 workflow/job occurrences (6 backend, 6 frontend) without explicit GITHUB_TOKEN permission scoping. This is a defense-in-depth control that limits the blast radius of a compromised workflow step.

**Expected risk reduction:** Reduces CI/CD supply chain risk by scoping GITHUB_TOKEN to minimum required permissions.

**Evidence:** `494149924f9b` (actions/missing-workflow-permissions, MEDIUM); `67272be356ee` (actions/missing-workflow-permissions, MEDIUM)

---

## Release Readiness Assessment

**Confidence:** HIGH

This release has multiple independent blocking conditions across application, infrastructure, runtime, and supply chain domains. At runtime, Kyverno confirms privilege escalation is live across 25+ pod locations. The backend has confirmed OS-command injection and hardcoded database credentials (SonarCloud BLOCKER, high confidence). GCP infrastructure has unrestricted internet-facing firewall rules and project-Owner IAM. Supply chain verification is UNKNOWN for both images and the runtime cosign enforcement is non-functional. No single one of these would be acceptable in isolation; together they represent a release that should not proceed to production without the blocking items resolved.

**Blocking evidence:** `f913039e3a2a` (disallow-privilege-escalation/privilege-escalation, CRITICAL); `73e307bc47c2` (disallow-privilege-escalation/autogen-privilege-escalation, CRITICAL); `688d20fa838a` (pythonsecurity:S2076, CRITICAL); `447335a06a0f` (pythonsecurity:S2083, CRITICAL); `049991827bea` (secrets:S6698, CRITICAL); `57df84a4027d` (CKV_GCP_3, CRITICAL); `dbbdc1cf61c2` (CKV_GCP_2, CRITICAL); `0487801b1fb6` (CKV_GCP_117, CRITICAL); `54c214b711d1` (CKV_GCP_49, CRITICAL); `189191849e41` (CKV_GCP_114, CRITICAL); `f84f2db980d4` (verify-image-cosign/verify-cosign-keyless-signature, CRITICAL); `3f6606939177` (verify-image-cosign/autogen-verify-cosign-keyless-signature, CRITICAL); `f1f751c2ee51` (CKV_GCP_69, HIGH)

**Conditions:**
- Resolve live privilege escalation: set allowPrivilegeEscalation: false on all deployed container specs (ACT-001)
- Disable Flask debug mode and suppress stack traces from HTTP responses (ACT-002)
- Rotate all exposed credentials and remove from source history; migrate to secret manager (ACT-003)
- Restrict GCP firewall rules to specific CIDRs and replace project-Owner IAM with minimum required role (ACT-004)
- Fix Artifact Registry IAM so cosign/Kyverno image verification is functional; confirm images are signed for this release commit (ACT-007)
- Remediate backend OS-command injection and path traversal vulnerabilities (ACT-006)
- Enable GKE Workload Identity to prevent pod-to-project-Owner privilege escalation via metadata server (ACT-005)

---

## Assumptions & Unknowns

- **`provenance.application_security.any_used_fallback_commit`** = `true` — All application security scan results (CodeQL, SonarCloud, GitGuardian, Snyk) come from a different commit (113d25cc) than this release (0b5819aa). Findings may not reflect code changes made between those two commits. The application security domain's findings should be treated as potentially incomplete or stale for any code changed after 113d25cc.
- **`provenance.infrastructure_security.version_matches_application_security`** = `false` — Infrastructure security scans (Checkov, kube-linter) ran against a different source version (921c68c) than the application security scans. The commits_behind value is null (could not be computed). The infrastructure findings may not reflect Terraform or Helm changes made after 921c68c, potentially understating or overstating the current infrastructure risk.
- **`provenance.infrastructure_security.source_generated_at`** = `"2026-06-27T07:34:21.609934+00:00"` — Infrastructure security scans were generated on 2026-06-27, approximately 28 days before this report (2026-07-25). Any Terraform or Helm changes in that window are not reflected in the infrastructure findings, reducing confidence in the infrastructure domain's completeness.
- **`supply_chain.backend.verification_status`** = `"UNKNOWN"` — Backend image supply chain verification returned UNKNOWN (manifest not found for the release commit tag). It is unknown whether the backend image was built from the expected source, signed, or even exists in the registry at this commit. This makes the container_security and runtime_security findings for the backend potentially moot if a different image is actually running.
- **`supply_chain.frontend.verification_status`** = `"UNKNOWN"` — Frontend image supply chain verification returned UNKNOWN for the same reason as backend. Combined with the Kyverno runtime finding that cosign verification is being denied due to IAM, there is no confirmed provenance for either deployed image.
- **`signal_availability.reachability`** = `"not_collected"` — Reachability is not collected. It is unknown which of the 139 vulnerable-dependency findings are actually reachable via exploitable code paths. This means the prioritization of dependency CVEs is based on severity alone, which may overstate risk for CVEs in code paths that are never exercised.
- **`signal_availability.exploitability`** = `"not_collected"` — Exploitability is not collected. No EPSS scores or exploit-in-the-wild data is available. The relative urgency of CVEs with available exploits versus theoretical ones cannot be differentiated in this report.
- **`signal_availability.business_impact`** = `"not_collected"` — Business impact is not collected. The criticality of individual components (e.g. whether the backend handles PII, financial data, or is internet-facing) is unknown. Risk prioritization assumes all components are equally business-critical.
- **`signal_availability.internet_exposure`** = `"not_collected"` — Internet exposure is not collected. It is unknown which services are directly internet-facing versus internal-only. The open firewall rules suggest broad exposure, but the actual routing topology (load balancer, ingress, etc.) is not confirmed.
- **`signal_availability.delta_status`** = `"not_collected"` — Delta status is not collected. It is unknown which findings are new in this release versus pre-existing. All 241 findings are treated as current, but some may be long-standing known issues with accepted risk, which would change the prioritization of remediation effort.
- **`sbom_summary.backend.packages_with_known_vulnerabilities`** = `["apt@2.6.1", "coreutils@9.1-1", "diffutils@1:3.8-4", "dpkg@1.21.22", "gzip@1.12-1", "libcap2@1:2.66-4", "libgcrypt20@1.10.1-3", "libtasn1-6@4.19.0-2", "openssl@3.0.9-1", "sed@4.9-1", "tar@1.34+dfsg-1.2"]` — The SBOM lists packages with known vulnerabilities (e.g. apt, coreutils, openssl, libgcrypt20) that do not all appear as individual findings in the findings array. The full OS-layer vulnerability surface may be larger than what is represented in the container_security findings.

---

## Final Recommendation

### ❌ DO NOT APPROVE

This release has multiple independent blocking conditions across application, infrastructure, runtime, and supply chain domains. At runtime, Kyverno confirms privilege escalation is live across 25+ pod locations. The backend has confirmed OS-command injection and hardcoded database credentials (SonarCloud BLOCKER, high confidence). GCP infrastructure has unrestricted internet-facing firewall rules and project-Owner IAM. Supply chain verification is UNKNOWN for both images and the runtime cosign enforcement is non-functional. No single one of these would be acceptable in isolation; together they represent a release that should not proceed to production without the blocking items resolved.
