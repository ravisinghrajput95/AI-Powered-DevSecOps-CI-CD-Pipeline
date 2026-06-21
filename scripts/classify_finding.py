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

    # Injection family
    (r"sql-injection|sql query.*user-provided|sql.*injection|injectable sql", "injection"),
    (r"construct the os command|command-line-injection|command line.*user-provided|os command.*user|shell.*injection|command injection", "injection"),
    (r"path-injection|construct the path from user-controlled|path depends on a.*user-provided|path traversal|directory traversal|zip.?slip", "path-traversal"),
    (r"full-ssrf|construct the url from user-controlled|url of this request depends on|server-side request forgery|\bssrf\b", "ssrf"),
    (r"reflective-xss|reflect unsanitized user-controlled|cross-site scripting|\bxss\b|dom-based xss|stored xss", "xss"),
    (r"\bcsrf\b|cross-site request forgery", "csrf"),
    (r"xml external entit|\bxxe\b", "xxe"),
    (r"deserialization.*untrusted|unsafe deserialization|pickle\.loads|yaml\.load\b", "insecure-deserialization"),

    # Crypto / TLS
    (r"weak-sensitive-data-hashing|insecure.*hash|\bmd5\b|\bsha1\b|weak.*crypto|insufficient.*entropy|weak random|insecure randomness", "insecure-crypto"),
    (r"certificate validation|ssl/tls|server certificate|hostname verification|insecure tls|tls.*disabled|verify=false", "insecure-tls"),

    # Info disclosure
    (r"stack-trace-exposure|stack trace.*expose|sensitive data.*log|information disclosure|verbose error", "info-disclosure"),
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


def classify_confidence(tool, severity):
    sev = (severity or "").lower()
    if tool == "gitguardian":
        return GITGUARDIAN_VALIDITY_CONFIDENCE.get(sev, "medium")
    if tool == "sonarcloud":
        return SONARCLOUD_SEVERITY_CONFIDENCE.get(sev, "medium")
    if tool == "codeql":
        return CODEQL_LEVEL_CONFIDENCE.get(sev, "medium")
    return "medium"


# ─────────────────────────────────────────────────────────────────
# RECOMMENDATION: short, generic fix-it text keyed by category.
# Intentionally generic (category-level, not rule-specific) since
# rule-specific remediation text would require a much larger mapping
# table than can be grounded in the data observed so far.
# ─────────────────────────────────────────────────────────────────
RECOMMENDATIONS_BY_CATEGORY = {
    "secret-exposure": "Remove the hardcoded credential from source control, rotate it at the provider, and load it from a secret manager or environment variable at runtime.",
    "injection": "Use parameterized queries or an ORM instead of building commands/queries via string concatenation with user input.",
    "path-traversal": "Validate and sanitize user-supplied paths against an allowlist; resolve and confirm the final path stays within an intended base directory.",
    "ssrf": "Validate and allowlist destination hosts/URLs before making outbound requests; never construct request URLs directly from unsanitized user input.",
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
    """Convenience wrapper returning (category, confidence, recommendation)."""
    category = classify_category(rule_id, message)
    confidence = classify_confidence(tool, severity)
    recommendation = classify_recommendation(category)
    return category, confidence, recommendation
