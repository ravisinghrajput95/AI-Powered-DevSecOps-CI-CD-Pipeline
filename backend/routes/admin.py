"""Admin dashboard - broken access control"""

import os
import subprocess

from flask import Blueprint, jsonify, request, session

from config import (
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    INTERNAL_SERVICES,
    SECRET_KEY,
    STRIPE_API_KEY,
)
from models.order import Order
from models.product import Product
from models.user import User, db

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/stats", methods=["GET"])
def admin_stats():
    """VULN: No admin role check"""
    return jsonify(
        {
            "users": User.query.count(),
            "products": Product.query.count(),
            "orders": Order.query.count(),
            "revenue": sum(float(o.total or 0) for o in Order.query.all()),
        }
    )


@admin_bp.route("/users", methods=["GET"])
def list_all_users():
    """VULN: Missing authorization - exposes all user data including hashes"""
    users = User.query.all()
    return jsonify([u.to_dict(include_sensitive=True) for u in users])


@admin_bp.route("/users/<int:user_id>/role", methods=["PUT"])
def update_user_role(user_id):
    """VULN: Privilege escalation - no auth required"""
    data = request.get_json() or {}
    user = User.query.get_or_404(user_id)
    user.role = data.get("role", user.role)
    db.session.commit()
    return jsonify(user.to_dict())


@admin_bp.route("/internal", methods=["GET"])
def internal_admin():
    """Internal endpoint - should not be exposed"""
    return jsonify(
        {
            "secret_key": SECRET_KEY,
            "aws_key": AWS_ACCESS_KEY,
            "aws_secret": AWS_SECRET_KEY,
            "stripe_key": STRIPE_API_KEY,
            "services": INTERNAL_SERVICES,
        }
    )


@admin_bp.route("/exec", methods=["POST"])
def admin_exec():
    """VULN: Command injection"""
    data = request.get_json() or {}
    command = data.get("command", "echo hello")
    # Intentionally dangerous
    result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    return jsonify({"output": result.decode("utf-8", errors="replace")})


@admin_bp.route("/env", methods=["GET"])
def admin_env():
    """VULN: Sensitive information exposure"""
    return jsonify(dict(os.environ))
