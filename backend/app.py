"""
CloudCart E-Commerce API
INTENTIONALLY INSECURE - DevSecOps Training Application
"""

import os
import time
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from config import SECRET_KEY, DEBUG, DATABASE_URL, METRICS_ENABLED
from models.user import db
from routes.auth import auth_bp
from routes.products import products_bp
from routes.cart import cart_bp
from routes.orders import orders_bp
from routes.reviews import reviews_bp
from routes.admin import admin_bp
from routes.vulnerable import vuln_bp
from routes.profile import profile_bp
from routes.metrics import metrics_bp, REQUEST_COUNT, REQUEST_LATENCY

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["DEBUG"] = DEBUG
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False

# VULN: CORS allows all origins
CORS(app, origins="*", supports_credentials=True)

db.init_app(app)

# Register blueprints
app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(products_bp, url_prefix="/api/products")
app.register_blueprint(cart_bp, url_prefix="/api/cart")
app.register_blueprint(orders_bp, url_prefix="/api/orders")
app.register_blueprint(reviews_bp, url_prefix="/api/reviews")
app.register_blueprint(admin_bp, url_prefix="/api/admin")
app.register_blueprint(vuln_bp, url_prefix="/api/vuln")
app.register_blueprint(profile_bp, url_prefix="/api/profile")
app.register_blueprint(metrics_bp)


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
        SECRET_KEY,
        JWT_SECRET,
        DATABASE_URL,
        AWS_ACCESS_KEY,
        AWS_SECRET_KEY,
        STRIPE_API_KEY,
        ADMIN_PASSWORD,
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
    """Ensure admin user exists with known password for demos."""
    from werkzeug.security import generate_password_hash

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


with app.app_context():
    from models.user import User

    db.create_all()
    seed_admin()


if __name__ == "__main__":
    # VULN: Debug mode with binding to all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
