# Release Intelligence Report

**Repository:** `ravisinghrajput95/AI-Powered-DevSecOps-CI-CD-Pipeline`
**Release Version:** `c4f0b852a3329bbde5ea78f60476d05701174931`
**Report Generated:** 2026-07-25T14:14:15.370332+00:00
**Report ID:** `798bc99d23f4ea72`
**Components Assessed:** backend, frontend, deployed-app, infrastructure, terraform

---

## Executive Summary

**Overall Health:** CRITICAL &nbsp;|&nbsp; **Deployment Confidence:** LOW

**Dominant Risk Themes:** Privilege escalation enabled across deployed workloads, Hardcoded secrets and credentials in source code, Severely outdated frontend dependencies (axios, dompurify, lodash), Critical OS-layer CVEs in backend container image, Open firewall rules and excessive IAM privileges in infrastructure, Container image signatures unverifiable at deploy time

This release presents a CRITICAL security posture across all five measured domains. The application layer carries multiple high-confidence critical findings: OS command injection and path traversal in the backend, XSS in both frontend and backend, and hardcoded PostgreSQL credentials committed to source. The frontend's npm dependency tree is severely outdated — axios 0.21.1 alone accounts for 28 CVEs spanning critical HTTP Response Splitting and Prototype Pollution through dozens of high/medium issues; dompurify 2.3.3 adds 22 more CVEs including XSS bypasses. The backend container image carries critical OS-layer vulnerabilities in openssl, gnutls28, krb5, and expat that are independently exploitable regardless of application-layer controls. At the infrastructure layer, Terraform configuration exposes unrestricted SSH/RDP/MySQL firewall rules, basic IAM roles at project level (effectively full project compromise if the node SA is exposed), and a publicly accessible storage bucket. The deployed workload fails Kyverno policy enforcement on privilege escalation, run-as-root, missing seccomp profiles, and capability dropping — meaning the live cluster is operating outside its own declared security policy. Supply chain verification for both backend and frontend images returned UNKNOWN (manifest not found), so it cannot be confirmed that what is running was built and signed by the expected CI pipeline. The combination of code-level injection vulnerabilities, committed secrets, unverified images, and a live cluster running with privilege escalation enabled makes this release not suitable for production deployment without significant remediation.

---

## Cross-Domain Analysis

### Privilege escalation: infra config gap confirmed by live runtime policy failure

**Affected domains:** infrastructure_security, runtime_security &nbsp;|&nbsp; **Confidence:** HIGH

Terraform configuration disables Workload Identity (GKE Metadata Server not enabled) and grants the compute service account basic Owner-level IAM roles at project level. This is independently confirmed at runtime by Kyverno policy failures showing allowPrivilegeEscalation is not set to false across 26+ workload locations. Together, these mean a container process that escalates privileges can also reach the GCE metadata server and obtain the node's over-privileged service account token, turning a container escape into a full project-level compromise.

**Business impact:** A single container breakout could yield full GCP project access, including all storage, databases, and compute resources.

**Recommended action:** Enable Workload Identity on the GKE cluster and node pool, replace the basic Owner IAM role with a least-privilege custom role, and set allowPrivilegeEscalation: false in all container securityContexts.

**Evidence:** `f1f751c2ee51` (CKV_GCP_69, HIGH); `54c214b711d1` (CKV_GCP_49, CRITICAL); `0487801b1fb6` (CKV_GCP_117, CRITICAL); `f913039e3a2a` (disallow-privilege-escalation/privilege-escalation, CRITICAL); `73e307bc47c2` (disallow-privilege-escalation/autogen-privilege-escalation, CRITICAL)

### Unsigned/unverifiable images compound all container-layer CVE risk

**Affected domains:** supply_chain, container_security, runtime_security &nbsp;|&nbsp; **Confidence:** HIGH

Supply chain verification for both backend and frontend images returned UNKNOWN — the release commit SHA was not found in Artifact Registry. Simultaneously, Kyverno's image signature verification policy is actively failing in the live cluster for the frontend image. This means there is no cryptographic assurance that the running images correspond to the CI-built artifacts that were scanned. The extensive container-layer CVE findings (critical openssl, gnutls28, krb5, expat in backend; nginx, libssh2, aom in frontend) were assessed against images whose provenance cannot be confirmed.

**Business impact:** If an attacker substituted a malicious image, the container-layer CVE scan results would be meaningless and the actual attack surface unknown.

**Recommended action:** Resolve the Artifact Registry manifest lookup failure (confirm the image was pushed with the correct tag/digest), ensure the cosign signing step ran successfully in CI for this exact digest, and fix the Kyverno image verification policy's registry access permissions.

**Evidence:** `f84f2db980d4` (verify-image-cosign/verify-cosign-keyless-signature, CRITICAL); `3f6606939177` (verify-image-cosign/autogen-verify-cosign-keyless-signature, CRITICAL); `80c766bd7abd` (SNYK-DEBIAN12-OPENSSL-15969314, CRITICAL); `9aeed721127a` (SNYK-DEBIAN12-GNUTLS28-16344303, CRITICAL); `903cec21ca4e` (SNYK-DEBIAN12-GNUTLS28-16344325, CRITICAL); `971307a2fb61` (SNYK-DEBIAN12-KRB5-7411315, CRITICAL)

### Hardcoded secrets in source code span application and container layers

**Affected domains:** application_security, container_security &nbsp;|&nbsp; **Confidence:** HIGH

SonarCloud detected a hardcoded PostgreSQL password (critical, high confidence) and a SECRET_KEY in the backend source. GitGuardian independently confirmed Username/Password and Generic Password patterns across both backend and frontend. These secrets are committed to the repository and will be baked into any container image built from this source, meaning they persist in image layers even if removed from the working tree. The backend container also runs with a writable root filesystem and without a read-only mount, making runtime secret extraction easier.

**Business impact:** Committed credentials provide direct database access to anyone with repository read access, and persist in container image history.

**Recommended action:** Immediately rotate all exposed credentials, remove them from source history (git filter-repo), load secrets from a secret manager at runtime, and set readOnlyRootFilesystem: true on all containers.

**Evidence:** `049991827bea` (secrets:S6698, CRITICAL); `ba3dc970c4bd` (python:S2068, MEDIUM); `00af2baa5ff3` (Username Password, MEDIUM); `45577584570d` (Generic Password, MEDIUM); `0ad3628d28ea` (Generic Password, MEDIUM); `878a66ae7816` (Username Password, MEDIUM); `7bb35e743f73` (no-read-only-root-fs, MEDIUM)

### Open firewall rules and missing network policy create unrestricted lateral movement surface

**Affected domains:** infrastructure_security, runtime_security &nbsp;|&nbsp; **Confidence:** HIGH

Terraform defines a google_compute_firewall.allow_all rule permitting unrestricted SSH, RDP, MySQL, FTP, and HTTP ingress from 0.0.0.0/0. At the cluster level, no Kubernetes NetworkPolicy is configured (missing-pod-isolation finding), and master authorized networks are not enabled. This means both the GCP network perimeter and the Kubernetes pod network are fully open, allowing any internet host to attempt SSH/RDP against nodes and any pod to reach any other pod.

**Business impact:** Unrestricted ingress enables direct brute-force or exploitation of node services; absence of NetworkPolicy means a compromised pod can reach all other workloads.

**Recommended action:** Replace the allow_all firewall rule with specific rules scoped to required ports and known CIDR ranges; enable master authorized networks; add Kubernetes NetworkPolicies to restrict pod-to-pod traffic to declared service dependencies only.

**Evidence:** `dbbdc1cf61c2` (CKV_GCP_2, CRITICAL); `3ba928b4fd97` (CKV_GCP_88, CRITICAL); `57df84a4027d` (CKV_GCP_3, CRITICAL); `382c6fe86e55` (CKV_GCP_77, HIGH); `7a97a533c5a2` (CKV_GCP_12, MEDIUM); `0d8acda49a79` (CKV_GCP_20, MEDIUM)

### Application-layer injection vulnerabilities confirmed by multiple independent tools

**Affected domains:** application_security &nbsp;|&nbsp; **Confidence:** HIGH

OS command injection is flagged by both SonarCloud (critical, BLOCKER) and CodeQL (medium, command-line-injection) in the backend. Path traversal is flagged by both SonarCloud (critical, 4 occurrences) and CodeQL (medium, 4 occurrences). SQL injection is flagged by CodeQL. XSS is flagged by SonarCloud in both backend and frontend, and independently by CodeQL (reflective XSS, bad-tag-filter). Cross-tool confirmation at different confidence levels on the same root causes significantly increases the credibility of these findings.

**Business impact:** Exploitable injection vulnerabilities in a deployed backend can lead to remote code execution, data exfiltration, and full application compromise.

**Recommended action:** Prioritize remediation of the OS command injection and SQL injection findings immediately; use parameterized queries, avoid shell construction from user input, and apply output encoding for all user-controlled data rendered in HTML/JS.

**Evidence:** `688d20fa838a` (pythonsecurity:S2076, CRITICAL); `6f568715650c` (py/command-line-injection, MEDIUM); `447335a06a0f` (pythonsecurity:S2083, CRITICAL); `9de17c0300aa` (py/path-injection, MEDIUM); `757685f73438` (py/sql-injection, MEDIUM); `b554580125be` (pythonsecurity:S5131, CRITICAL); `6751a218019c` (jssecurity:S5696, CRITICAL); `4825cf439910` (py/reflective-xss, MEDIUM)

---

## Top Risks

### Risk 1: OS command injection and SQL injection in deployed backend

**Confidence:** HIGH

**Impact:** Remote code execution and data exfiltration from the live backend service.

**Why it matters:** Command injection confirmed at critical severity by SonarCloud and corroborated by CodeQL; SQL injection confirmed by CodeQL. These are directly exploitable via the application's HTTP interface with no prerequisite access. The backend is deployed and reachable.

**Recommended action:** Immediately audit and remediate all code paths constructing OS commands or SQL queries from user input; use parameterized queries and subprocess argument lists (never shell=True with user data).

**Evidence:** `688d20fa838a` (pythonsecurity:S2076, CRITICAL); `6f568715650c` (py/command-line-injection, MEDIUM); `757685f73438` (py/sql-injection, MEDIUM)

### Risk 2: Hardcoded PostgreSQL password and SECRET_KEY committed to source

**Confidence:** HIGH

**Impact:** Direct database compromise and session/token forgery for anyone with repository read access.

**Why it matters:** Critical-severity, high-confidence finding from SonarCloud with 4 occurrences of the PostgreSQL password pattern. Independently corroborated by GitGuardian across both components. Credentials baked into source are also baked into container image layers.

**Recommended action:** Rotate all exposed credentials immediately, purge from git history, and inject secrets at runtime via a secret manager (e.g. GCP Secret Manager, Kubernetes Secrets with external-secrets-operator).

**Evidence:** `049991827bea` (secrets:S6698, CRITICAL); `ba3dc970c4bd` (python:S2068, MEDIUM); `00af2baa5ff3` (Username Password, MEDIUM); `45577584570d` (Generic Password, MEDIUM)

### Risk 3: Privilege escalation enabled across all deployed workloads

**Confidence:** HIGH

**Impact:** Any container process can gain elevated privileges, enabling container escape and lateral movement to the over-privileged node service account.

**Why it matters:** Kyverno policy enforcement is actively failing for allowPrivilegeEscalation across 26+ workload locations in the live cluster. Combined with Workload Identity being disabled and the node SA holding basic Owner IAM role, privilege escalation leads directly to full GCP project compromise.

**Recommended action:** Set allowPrivilegeEscalation: false in all container securityContexts immediately; enable Workload Identity on the cluster; replace the basic Owner IAM role with a least-privilege role.

**Evidence:** `f913039e3a2a` (disallow-privilege-escalation/privilege-escalation, CRITICAL); `73e307bc47c2` (disallow-privilege-escalation/autogen-privilege-escalation, CRITICAL); `f1f751c2ee51` (CKV_GCP_69, HIGH); `54c214b711d1` (CKV_GCP_49, CRITICAL); `0487801b1fb6` (CKV_GCP_117, CRITICAL)

### Risk 4: Critical OS-layer CVEs in backend container image (openssl, gnutls28, krb5, expat)

**Confidence:** HIGH

**Impact:** Exploitable vulnerabilities in core cryptographic and parsing libraries present in the running backend container.

**Why it matters:** Multiple critical CVEs in openssl (CVE-2026-31789), gnutls28 (CVE-2026-42010, CVE-2026-33845), krb5 (CVE-2024-37371), and expat (CVE-2024-45491/45492) are present in the backend image. These are OS-layer packages used by many application components and are independently exploitable. Image provenance is UNKNOWN, so the actual running image may differ from what was scanned.

**Recommended action:** Rebuild the backend container from an updated base image with patched OS packages; establish a regular base image update cadence and automate OS-layer vulnerability scanning as a build gate.

**Evidence:** `80c766bd7abd` (SNYK-DEBIAN12-OPENSSL-15969314, CRITICAL); `9aeed721127a` (SNYK-DEBIAN12-GNUTLS28-16344303, CRITICAL); `903cec21ca4e` (SNYK-DEBIAN12-GNUTLS28-16344325, CRITICAL); `971307a2fb61` (SNYK-DEBIAN12-KRB5-7411315, CRITICAL); `406f0f4dac9b` (SNYK-DEBIAN12-EXPAT-7855502, CRITICAL); `afabe834cfa4` (SNYK-DEBIAN12-EXPAT-7855503, CRITICAL)

### Risk 5: Container image signatures unverifiable; Kyverno image policy actively failing

**Confidence:** HIGH

**Impact:** No cryptographic assurance that deployed images were built by the expected CI pipeline; supply chain substitution cannot be detected.

**Why it matters:** Both backend and frontend supply_chain.verification_status is UNKNOWN (manifest not found in Artifact Registry). Kyverno's cosign keyless signature verification policy is actively failing in the live cluster for the frontend image, and the error indicates an Artifact Registry permission denial. This means the image verification control is non-functional.

**Recommended action:** Resolve the Artifact Registry IAM permission for the Kyverno service account; confirm the cosign signing step ran for the exact deployed digest; investigate why the release SHA is not found in the registry.

**Evidence:** `f84f2db980d4` (verify-image-cosign/verify-cosign-keyless-signature, CRITICAL); `3f6606939177` (verify-image-cosign/autogen-verify-cosign-keyless-signature, CRITICAL)

### Risk 6: Unrestricted firewall rules expose SSH, RDP, MySQL, and FTP to the internet

**Confidence:** HIGH

**Impact:** Direct internet-accessible attack surface on node management ports and database services.

**Why it matters:** google_compute_firewall.allow_all permits 0.0.0.0/0 ingress on SSH (critical), RDP (critical), MySQL (critical), and FTP (high) ports. These are the highest-value targets for automated internet scanning and brute-force attacks.

**Recommended action:** Replace allow_all with specific firewall rules scoped to required source CIDRs; remove SSH/RDP/MySQL/FTP from public ingress entirely and use IAP or VPN for administrative access.

**Evidence:** `dbbdc1cf61c2` (CKV_GCP_2, CRITICAL); `3ba928b4fd97` (CKV_GCP_88, CRITICAL); `57df84a4027d` (CKV_GCP_3, CRITICAL); `382c6fe86e55` (CKV_GCP_77, HIGH); `e5f32d7b4723` (CKV_GCP_75, HIGH)

### Risk 7: Frontend axios 0.21.1 carries 28 CVEs including critical HTTP Response Splitting and Prototype Pollution

**Confidence:** HIGH

**Impact:** Client-side request manipulation, prototype pollution enabling logic bypass, and sensitive data leakage in the frontend application.

**Why it matters:** A single package upgrade resolves 28 CVEs spanning critical through medium severity. The package is severely outdated (0.21.1 vs. current 1.x series). Critical CVEs include HTTP Response Splitting (CVE-2026-42035) and Prototype Pollution (CVE-2026-42033).

**Recommended action:** Upgrade axios to 1.18.0 or later (resolves all known CVEs in the finding set); pin the version in package.json and lock with package-lock.json.

**Evidence:** `0dc16d7ed2e9` (SNYK-JS-AXIOS-16298058, CRITICAL); `a7b165255456` (SNYK-JS-AXIOS-16299904, CRITICAL); `472ae7a3640e` (SNYK-JS-AXIOS-15252993, HIGH); `301f4d9e8a0f` (SNYK-JS-AXIOS-1579269, HIGH); `21c208e62117` (SNYK-JS-AXIOS-17111062, HIGH)

### Risk 8: XSS vulnerabilities in both backend and frontend confirmed by multiple tools

**Confidence:** HIGH

**Impact:** Arbitrary JavaScript execution in user browsers, enabling session hijacking, credential theft, and malicious redirects.

**Why it matters:** Backend XSS confirmed at critical severity by SonarCloud and corroborated by CodeQL. Frontend XSS confirmed at critical severity by SonarCloud. dompurify 2.3.3 (the library intended to prevent XSS) itself carries multiple XSS CVEs, undermining the sanitization layer.

**Recommended action:** Apply output encoding for all user-controlled data in templates; upgrade dompurify to 3.4.12 or later; audit all innerHTML/dangerouslySetInnerHTML usages.

**Evidence:** `b554580125be` (pythonsecurity:S5131, CRITICAL); `6751a218019c` (jssecurity:S5696, CRITICAL); `4825cf439910` (py/reflective-xss, MEDIUM); `82d7f2881d4c` (SNYK-JS-DOMPURIFY-8318045, CRITICAL); `872764e9621e` (SNYK-JS-DOMPURIFY-8184974, MEDIUM)

---

## Highest Priority Actions

### Action 1: Rotate and externalize all hardcoded credentials (PostgreSQL password, SECRET_KEY)

**Estimated complexity:** MEDIUM &nbsp;|&nbsp; **Dependencies:** none

Committed credentials are immediately exploitable by anyone with repository access and persist in container image layers. This is the highest-urgency action because it requires no code change to exploit and the blast radius includes the database.

**Expected risk reduction:** Eliminates direct database compromise risk from credential exposure; removes RISK-002 and reduces CORR-003.

**Evidence:** `049991827bea` (secrets:S6698, CRITICAL); `ba3dc970c4bd` (python:S2068, MEDIUM); `00af2baa5ff3` (Username Password, MEDIUM); `45577584570d` (Generic Password, MEDIUM); `0ad3628d28ea` (Generic Password, MEDIUM); `878a66ae7816` (Username Password, MEDIUM)

### Action 2: Remediate OS command injection and SQL injection in backend

**Estimated complexity:** MEDIUM &nbsp;|&nbsp; **Dependencies:** none

Critical-severity, high-confidence, cross-tool confirmed injection vulnerabilities in a deployed service represent the most direct path to remote code execution. Must be fixed before any production traffic is served.

**Expected risk reduction:** Eliminates RISK-001; removes the highest-severity application-layer attack vector.

**Evidence:** `688d20fa838a` (pythonsecurity:S2076, CRITICAL); `6f568715650c` (py/command-line-injection, MEDIUM); `757685f73438` (py/sql-injection, MEDIUM); `447335a06a0f` (pythonsecurity:S2083, CRITICAL); `9de17c0300aa` (py/path-injection, MEDIUM)

### Action 3: Set allowPrivilegeEscalation: false and runAsNonRoot: true on all container securityContexts

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

Live Kyverno policy enforcement is failing across 26+ workload locations. Combined with disabled Workload Identity and over-privileged node SA, this is the shortest path from container process to full GCP project compromise.

**Expected risk reduction:** Eliminates RISK-003; breaks the privilege escalation chain described in CORR-001.

**Evidence:** `f913039e3a2a` (disallow-privilege-escalation/privilege-escalation, CRITICAL); `73e307bc47c2` (disallow-privilege-escalation/autogen-privilege-escalation, CRITICAL); `55a0910c0cd3` (require-run-as-nonroot/run-as-non-root, HIGH); `79abedf3ae77` (require-run-as-nonroot/autogen-run-as-non-root, HIGH); `a37e4f16b0ef` (run-as-non-root, HIGH)

### Action 4: Enable Workload Identity and replace basic Owner IAM role with least-privilege role

**Estimated complexity:** MEDIUM &nbsp;|&nbsp; **Dependencies:** ACT-003

Workload Identity disabled means all pods inherit the node's Compute Engine SA. That SA holds basic Owner role at project level. Fixing this severs the privilege escalation-to-project-compromise chain even if a container escape occurs.

**Expected risk reduction:** Reduces blast radius of any container compromise from full project access to scoped workload permissions; addresses CORR-001.

**Evidence:** `f1f751c2ee51` (CKV_GCP_69, HIGH); `54c214b711d1` (CKV_GCP_49, CRITICAL); `0487801b1fb6` (CKV_GCP_117, CRITICAL)

### Action 5: Replace allow_all firewall rule with scoped rules; remove public SSH/RDP/MySQL/FTP ingress

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

Unrestricted internet ingress on management and database ports is a critical infrastructure exposure. This is a Terraform change that can be applied immediately without application changes.

**Expected risk reduction:** Eliminates RISK-006; removes internet-accessible attack surface on node management and database ports.

**Evidence:** `dbbdc1cf61c2` (CKV_GCP_2, CRITICAL); `3ba928b4fd97` (CKV_GCP_88, CRITICAL); `57df84a4027d` (CKV_GCP_3, CRITICAL); `382c6fe86e55` (CKV_GCP_77, HIGH); `e5f32d7b4723` (CKV_GCP_75, HIGH)

### Action 6: Upgrade frontend axios to ≥1.18.0, dompurify to ≥3.4.12, lodash to ≥4.18.1, moment to ≥2.29.4

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

Four npm packages account for the majority of frontend CVEs. Each is a single version bump that resolves multiple CVEs simultaneously. axios alone resolves 28 CVEs including two critical ones.

**Expected risk reduction:** Resolves RISK-007 and substantially reduces frontend application_security and container_security finding counts; addresses the bulk of frontend vulnerable-dependency findings.

**Evidence:** `0dc16d7ed2e9` (SNYK-JS-AXIOS-16298058, CRITICAL); `a7b165255456` (SNYK-JS-AXIOS-16299904, CRITICAL); `82d7f2881d4c` (SNYK-JS-DOMPURIFY-8318045, CRITICAL); `6ad0842ac459` (SNYK-JS-LODASH-1040724, HIGH); `69e3a556368e` (SNYK-JS-LODASH-15869625, HIGH); `a6a58d1a71c4` (SNYK-JS-MOMENT-2440688, HIGH); `61c29417af07` (SNYK-JS-MOMENT-2944238, HIGH)

### Action 7: Rebuild backend container from updated base image to patch OS-layer CVEs (openssl, gnutls28, krb5, expat, pam)

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

Critical and high OS-layer CVEs in core cryptographic and authentication libraries cannot be fixed at the application level. A base image rebuild with current Debian 12 packages resolves the majority of container_security findings in a single operation.

**Expected risk reduction:** Eliminates RISK-004; resolves the majority of container_security critical and high findings for the backend.

**Evidence:** `80c766bd7abd` (SNYK-DEBIAN12-OPENSSL-15969314, CRITICAL); `9aeed721127a` (SNYK-DEBIAN12-GNUTLS28-16344303, CRITICAL); `903cec21ca4e` (SNYK-DEBIAN12-GNUTLS28-16344325, CRITICAL); `971307a2fb61` (SNYK-DEBIAN12-KRB5-7411315, CRITICAL); `406f0f4dac9b` (SNYK-DEBIAN12-EXPAT-7855502, CRITICAL); `afabe834cfa4` (SNYK-DEBIAN12-EXPAT-7855503, CRITICAL); `ad17eeee434e` (SNYK-DEBIAN12-PAM-10378969, HIGH)

### Action 8: Resolve image signing and Artifact Registry verification failures

**Estimated complexity:** MEDIUM &nbsp;|&nbsp; **Dependencies:** none

Supply chain verification is UNKNOWN for both images and Kyverno's cosign policy is actively failing. Until this is resolved, there is no assurance that what is running in the cluster matches what was scanned.

**Expected risk reduction:** Eliminates RISK-005; restores supply chain integrity assurance and makes CORR-002 moot.

**Evidence:** `f84f2db980d4` (verify-image-cosign/verify-cosign-keyless-signature, CRITICAL); `3f6606939177` (verify-image-cosign/autogen-verify-cosign-keyless-signature, CRITICAL)

### Action 9: Remediate XSS in backend and frontend; upgrade dompurify

**Estimated complexity:** MEDIUM &nbsp;|&nbsp; **Dependencies:** ACT-006

Critical XSS confirmed by multiple tools in both components. The sanitization library (dompurify) itself is vulnerable, undermining the defense-in-depth layer. Must be fixed before serving untrusted user content.

**Expected risk reduction:** Eliminates RISK-008; removes client-side code execution vectors.

**Evidence:** `b554580125be` (pythonsecurity:S5131, CRITICAL); `6751a218019c` (jssecurity:S5696, CRITICAL); `4825cf439910` (py/reflective-xss, MEDIUM); `82d7f2881d4c` (SNYK-JS-DOMPURIFY-8318045, CRITICAL); `36df65e5cd25` (py/bad-tag-filter, MEDIUM)

### Action 10: Upgrade backend Python dependencies: pillow to ≥12.3.0, cryptography to ≥48.0.1, flask-cors to ≥6.0.0

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

Three pip packages account for the majority of backend application-layer CVEs. pillow 11.3.0 carries 16 findings (high/medium); cryptography 43.0.3 carries 4; flask-cors 4.0.2 carries 4. Each is a single version bump.

**Expected risk reduction:** Resolves the majority of backend application_security vulnerable-dependency findings.

**Evidence:** `524835b29043` (SNYK-PYTHON-PILLOW-15265439, HIGH); `8891af27bcb3` (SNYK-PYTHON-PILLOW-16032068, HIGH); `0b2ca1c5c052` (SNYK-PYTHON-PILLOW-16419303, HIGH); `574389232a75` (SNYK-PYTHON-CRYPTOGRAPHY-15263096, HIGH); `ca8ca4aa1e13` (SNYK-PYTHON-CRYPTOGRAPHY-17344551, HIGH); `b3a42d493492` (SNYK-PYTHON-FLASKCORS-7707876, HIGH); `d6fc6f9489fe` (SNYK-PYTHON-FLASKCORS-9668954, HIGH)

### Action 11: Add explicit permissions blocks to all GitHub Actions workflows

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

12 CI workflow jobs (6 backend, 6 frontend) lack explicit GITHUB_TOKEN permission scoping, granting broader-than-necessary token access to every job. This is a low-effort hardening step.

**Expected risk reduction:** Reduces CI/CD supply chain attack surface; resolves all ci-misconfiguration findings.

**Evidence:** `494149924f9b` (actions/missing-workflow-permissions, MEDIUM); `67272be356ee` (actions/missing-workflow-permissions, MEDIUM)

### Action 12: Disable Flask debug mode and remove stack trace exposure in production

**Estimated complexity:** LOW &nbsp;|&nbsp; **Dependencies:** none

Flask debug mode enables the Werkzeug interactive debugger, which allows arbitrary code execution by anyone who can reach the debug endpoint. Stack trace exposure leaks internal implementation details to attackers.

**Expected risk reduction:** Eliminates remote code execution via debug endpoint; reduces information disclosure.

**Evidence:** `217911839f44` (py/flask-debug, MEDIUM); `c504da4d8155` (py/stack-trace-exposure, MEDIUM); `0c9c83aacaa9` (docker:S4507, LOW)

---

## Release Readiness Assessment

**Confidence:** HIGH

This release has multiple independent blocking conditions across application, infrastructure, runtime, and supply chain domains, all at high confidence. Critical injection vulnerabilities (OS command injection, SQL injection) are confirmed by two independent tools in the deployed backend. Hardcoded database credentials are committed to source. The live cluster is actively failing Kyverno privilege escalation policy enforcement across 26+ workload locations. Infrastructure Terraform exposes unrestricted SSH/RDP/MySQL firewall rules and grants basic Owner IAM at project level. Container image supply chain verification is UNKNOWN for both images, and the Kyverno cosign policy is non-functional. No single one of these conditions alone would be acceptable for production; together they represent a release that is not safe to deploy or leave running in its current state.

**Blocking evidence:** `688d20fa838a` (pythonsecurity:S2076, CRITICAL); `049991827bea` (secrets:S6698, CRITICAL); `f913039e3a2a` (disallow-privilege-escalation/privilege-escalation, CRITICAL); `73e307bc47c2` (disallow-privilege-escalation/autogen-privilege-escalation, CRITICAL); `dbbdc1cf61c2` (CKV_GCP_2, CRITICAL); `54c214b711d1` (CKV_GCP_49, CRITICAL); `0487801b1fb6` (CKV_GCP_117, CRITICAL); `f84f2db980d4` (verify-image-cosign/verify-cosign-keyless-signature, CRITICAL); `3f6606939177` (verify-image-cosign/autogen-verify-cosign-keyless-signature, CRITICAL); `217911839f44` (py/flask-debug, MEDIUM)

**Conditions:**
- Rotate and externalize all hardcoded credentials (PostgreSQL password, SECRET_KEY) and confirm they are no longer present in source or image layers.
- Remediate OS command injection and SQL injection in the backend before serving any production traffic.
- Set allowPrivilegeEscalation: false and runAsNonRoot: true on all container securityContexts so Kyverno policy enforcement passes.
- Replace the allow_all firewall rule with scoped rules that do not expose SSH, RDP, MySQL, or FTP to 0.0.0.0/0.
- Resolve the Artifact Registry image manifest lookup failure and confirm cosign signing ran successfully for the exact deployed digest.
- Disable Flask debug mode in the production deployment configuration.
- Enable Workload Identity on the GKE cluster and replace the basic Owner IAM role with a least-privilege role.
- Upgrade axios, dompurify, lodash, and moment in the frontend to versions that resolve all critical CVEs.
- Rebuild the backend container from an updated base image to patch critical OS-layer CVEs in openssl, gnutls28, krb5, and expat.

---

## Assumptions & Unknowns

- **`provenance.application_security.any_used_fallback_commit`** = `true` — All four application security workflows ran against a different commit (8827a89e) than this release (c4f0b852). Findings may not reflect code changes introduced between those commits and this release. Application security findings could be understated or overstated relative to the actual release state.
- **`provenance.infrastructure_security.version_matches_application_security`** = `false` — Infrastructure security scans ran against a different source version than application security scans. While this is expected behavior per the provenance note, it means infra findings may not reflect any Terraform/Helm changes made in commits between the infra scan and this release.
- **`provenance.infrastructure_security.commits_behind`** = _[pointer did not resolve against final_release_context.json]_ — The number of commits between the infrastructure scan version and the release version could not be computed. The degree of drift between scanned and released infrastructure configuration is unknown; the infra findings may be stale.
- **`signal_availability.reachability`** = `"not_collected"` — Reachability is not collected for any finding. Injection, XSS, SSRF, and path traversal findings cannot be confirmed as reachable from an external attacker's perspective. Prioritization is based on severity and cross-tool confirmation only; some findings may be in dead code paths.
- **`signal_availability.exploitability`** = `"not_collected"` — Exploitability is not collected. No CVSS temporal or environmental scores, no exploit-in-the-wild data, and no proof-of-concept availability information is available. Risk prioritization relies on base severity only, which may over- or under-weight specific CVEs.
- **`signal_availability.business_impact`** = `"not_collected"` — Business impact is not collected. The report cannot distinguish between findings affecting a revenue-critical path versus a low-traffic internal endpoint. All components are treated as equally business-critical.
- **`signal_availability.internet_exposure`** = `"not_collected"` — Internet exposure is not collected. It is assumed the deployed-app is internet-facing based on the ZAP scan and the open firewall rules, but this is an inference. If certain components are internal-only, their risk priority may be lower than assessed.
- **`signal_availability.delta_status`** = `"not_collected"` — Delta status (new vs. pre-existing findings) is not collected. It is unknown which findings are regressions introduced by this release versus pre-existing technical debt. This prevents the report from distinguishing release-introduced risk from baseline risk.
- **`supply_chain.backend.verification_status`** = `"UNKNOWN"` — Backend image verification status is UNKNOWN due to a manifest lookup failure. All container_security findings for the backend were assessed against an image whose identity cannot be confirmed. If the running image differs from the scanned image, the actual container-layer attack surface is unknown.
- **`supply_chain.frontend.verification_status`** = `"UNKNOWN"` — Frontend image verification status is UNKNOWN for the same reason as backend. Additionally, the Kyverno cosign policy is actively failing with an Artifact Registry permission denial, meaning the runtime image verification control is non-functional and cannot be relied upon as a compensating control.
- **`sbom_summary.backend.packages_with_known_vulnerabilities`** = `["apt@2.6.1", "coreutils@9.1-1", "diffutils@1:3.8-4", "dpkg@1.21.22", "gzip@1.12-1", "libcap2@1:2.66-4", "libgcrypt20@1.10.1-3", "libtasn1-6@4.19.0-2", "openssl@3.0.9-1", "sed@4.9-1", "tar@1.34+dfsg-1.2"]` — The SBOM lists packages with known vulnerabilities (e.g. apt, coreutils, openssl, libgcrypt20) that do not all appear as individual findings in the findings array. The full scope of OS-layer vulnerability exposure in the backend image may be broader than what the container_security findings alone represent.
- **`sbom_summary.frontend.packages_with_known_vulnerabilities`** = `["apt@3.0.3", "coreutils@9.7-3", "curl@8.14.1-2+deb13u4", "diffutils@1:3.10-4", "gzip@1.13-1", "libgcrypt20@1.11.0-7+deb13u1", "libxml2@2.12.7+dfsg+really2.9.14-2.1+deb13u3", "nginx@1.31.3-1~trixie", "tar@1.35+dfsg-3.1", "util-linux@2.41-5"]` — Similarly, the frontend SBOM lists packages (curl, libxml2, util-linux, nginx) with known vulnerabilities. The nginx finding does appear in findings, but others may represent additional unscored exposure not fully captured in the findings array.

---

## Final Recommendation

### ❌ DO NOT APPROVE

This release has multiple independent blocking conditions across application, infrastructure, runtime, and supply chain domains, all at high confidence. Critical injection vulnerabilities (OS command injection, SQL injection) are confirmed by two independent tools in the deployed backend. Hardcoded database credentials are committed to source. The live cluster is actively failing Kyverno privilege escalation policy enforcement across 26+ workload locations. Infrastructure Terraform exposes unrestricted SSH/RDP/MySQL firewall rules and grants basic Owner IAM at project level. Container image supply chain verification is UNKNOWN for both images, and the Kyverno cosign policy is non-functional. No single one of these conditions alone would be acceptable for production; together they represent a release that is not safe to deploy or leave running in its current state.
