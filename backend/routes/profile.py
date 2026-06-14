"""User profile routes"""

from flask import Blueprint, jsonify, request, session
from werkzeug.security import generate_password_hash

from models.user import User, db

profile_bp = Blueprint("profile", __name__)


@profile_bp.route("/<int:user_id>", methods=["GET"])
def get_profile(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict(include_sensitive=request.args.get("full") == "true"))


@profile_bp.route("/<int:user_id>", methods=["PUT"])
def update_profile(user_id):
    # VULN: Broken access control - can update any profile
    user = User.query.get_or_404(user_id)
    data = request.get_json() or {}

    if "full_name" in data:
        user.full_name = data["full_name"]
    if "email" in data:
        user.email = data["email"]
    if "password" in data:
        user.password_hash = generate_password_hash(data["password"])
    if "role" in data:
        user.role = data["role"]

    db.session.commit()
    return jsonify(user.to_dict())


@profile_bp.route("/<int:user_id>/api-key", methods=["GET"])
def get_api_key(user_id):
    """VULN: Exposes API keys without proper auth"""
    user = User.query.get_or_404(user_id)
    return jsonify({"api_key": user.api_key})
