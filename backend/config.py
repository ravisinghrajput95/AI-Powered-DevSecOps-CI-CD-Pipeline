"""
CloudCart Configuration
INTENTIONALLY INSECURE - For DevSecOps training only
"""

import os

# VULN: Hardcoded secrets
SECRET_KEY = "cloudcart-super-secret-key-12345-do-not-share"
JWT_SECRET = "jwt-secret-hardcoded-in-source-code"
# Default: localhost (local dev). Docker Compose sets DATABASE_URL to host "postgres".
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://cloudcart:CloudCartDB_Pass123!@localhost:5432/cloudcart",
)
ADMIN_PASSWORD = "admin123"
STRIPE_API_KEY = "sk_live_51HCloudCartFakeStripeKeyForTraining"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_CloudCartFakeGitHubTokenForGitleaksDemo1234567890"

# VULN: Debug mode enabled in production config
DEBUG = True
FLASK_ENV = "development"

# VULN: Weak session configuration
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SAMESITE = None
PERMANENT_SESSION_LIFETIME = 86400 * 365  # 1 year - too long

# Upload settings - intentionally permissive
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB - too large
ALLOWED_EXTENSIONS = set()  # Empty = allow all file types

# Internal services for SSRF demo
INTERNAL_SERVICES = {
    "metadata": "http://169.254.169.254/latest/meta-data/",
    "admin_panel": "http://backend:5000/api/admin/internal",
    "postgres": "postgresql://cloudcart:CloudCartDB_Pass123!@postgres:5432/cloudcart",
}

# Prometheus
METRICS_ENABLED = True
