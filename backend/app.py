"""
CloudCart E-Commerce API
INTENTIONALLY INSECURE - DevSecOps Training Application
"""

import os
import time

from flask import Flask, g, jsonify, request
from flask_cors import CORS

from config import DATABASE_URL, DEBUG, METRICS_ENABLED, SECRET_KEY
from models.user import db
from routes.admin import admin_bp
from routes.auth import auth_bp
from routes.cart import cart_bp
from routes.metrics import REQUEST_COUNT, REQUEST_LATENCY, metrics_bp
from routes.orders import orders_bp
from routes.products import products_bp
from routes.profile import profile_bp
from routes.reviews import reviews_bp
from routes.vulnerable import vuln_bp


def create_app(config_overrides=None, init_db=True):
    """Application factory.

    Previously this module built the app at import time and, at the bottom,
    ran `db.create_all()` and `seed_admin()` inside a `with app.app_context()`
    block. That meant importing app.py opened a real database connection, so:

      - tests could not import the app without a live database, which is why
        backend/tests only ever asserted on module structure
      - every gunicorn worker re-ran create_all() and the admin seed on boot
      - `seed_admin()` referenced `User`, which only became a module global
        because of an import several lines BELOW the function definition —
        it worked purely by call ordering

    None of the intentional vulnerabilities change here. The insecure CORS,
    session flags, debug mode, hardcoded config and /api/config exposure are
    all preserved exactly; only the initialisation side effects move behind
    an explicit call.

    init_db=False lets tests build a real app (and use test_client) without
    touching a database.
    """
    app = Flask(__name__)
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["DEBUG"] = DEBUG
    # VULN: insecure session cookies (unchanged)
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = False
    if config_overrides:
        app.config.update(config_overrides)

    # VULN: CORS allows all origins (unchanged)
    CORS(app, origins="*", supports_credentials=True)

    db.init_app(app)

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(products_bp, url_prefix="/api/products")
    app.register_blueprint(cart_bp, url_prefix="/api/cart")
    app.register_blueprint(orders_bp, url_prefix="/api/orders")
    app.register_blueprint(reviews_bp, url_prefix="/api/reviews")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")
    app.register_blueprint(vuln_bp, url_prefix="/api/vuln")
    app.register_blueprint(profile_bp, url_prefix="/api/profile")
    app.register_blueprint(metrics_bp)

    register_request_hooks(app)
    register_core_routes(app)

    if init_db:
        with app.app_context():
            db.create_all()
            seed_admin()

    return app


def register_request_hooks(app):
    @app.before_request
    def before_request():
        g.start_time = time.time()

    @app.after_request
    def after_request(response):
        if METRICS_ENABLED and request.endpoint:
            duration = time.time() - g.get("start_time", time.time())
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.endpoint or "unknown",
                status=response.status_code,
            ).inc()
            REQUEST_LATENCY.labels(
                method=request.method,
                endpoint=request.endpoint or "unknown",
            ).observe(duration)
        return response


def register_core_routes(app):
    @app.route("/health")
    def health():
        return jsonify({"status": "healthy", "service": "cloudcart-api"})

    @app.route("/")
    def index():
        return jsonify(
            {
                "name": "CloudCart API",
                "version": "1.0.0",
                "warning": "INTENTIONALLY INSECURE - DevSecOps training only",
                "endpoints": {
                    "auth": "/api/auth",
                    "products": "/api/products",
                    "cart": "/api/cart",
                    "orders": "/api/orders",
                    "reviews": "/api/reviews",
                    "admin": "/api/admin",
                    "metrics": "/metrics",
                },
            }
        )

    @app.route("/api/config")
    def expose_config():
        """VULN: Sensitive information exposure"""
        from config import (
            ADMIN_PASSWORD,
            AWS_ACCESS_KEY,
            AWS_SECRET_KEY,
            DATABASE_URL,
            JWT_SECRET,
            SECRET_KEY,
            STRIPE_API_KEY,
        )

        return jsonify(
            {
                "secret_key": SECRET_KEY,
                "jwt_secret": JWT_SECRET,
                "database_url": DATABASE_URL,
                "aws_access_key": AWS_ACCESS_KEY,
                "aws_secret_key": AWS_SECRET_KEY,
                "stripe_api_key": STRIPE_API_KEY,
                "admin_password": ADMIN_PASSWORD,
                "debug": DEBUG,
            }
        )


def seed_admin():
    """Ensure admin user exists with known password for demos.

    `User` is imported here rather than relied upon as a module global set
    by an import lower down the file — the previous arrangement only worked
    because of call ordering.
    """
    from werkzeug.security import generate_password_hash

    from models.user import User

    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            email="admin@cloudcart.local",
            password_hash=generate_password_hash("admin123"),
            full_name="CloudCart Admin",
            role="admin",
            api_key="sk_live_cloudcart_admin_key_DO_NOT_USE_IN_PROD",
        )
        db.session.add(admin)
        db.session.commit()


# Deliberately NO module-level `app = create_app()`. Instantiating at import
# time is what made this module impossible to import without a live database,
# and it re-ran create_all() + seed_admin() in every gunicorn worker.
# Entry points construct the app explicitly:
#   - gunicorn -> wsgi.py
#   - `python app.py` -> below
if __name__ == "__main__":
    # VULN: Debug mode with binding to all interfaces
    create_app().run(host="0.0.0.0", port=5000, debug=True)
