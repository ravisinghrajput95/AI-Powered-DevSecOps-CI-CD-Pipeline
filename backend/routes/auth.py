"""Authentication routes - weak session management"""

import hashlib
from datetime import datetime, timedelta

import jwt
from flask import Blueprint, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from config import DEBUG, JWT_SECRET, SECRET_KEY
from models.user import User, db

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "")
    email = data.get("email", "")
    password = data.get("password", "")
    full_name = data.get("full_name", "")

    if not username or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 409

    user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        full_name=full_name,
        role="customer",
        api_key=f"sk_live_{hashlib.md5(username.encode()).hexdigest()}",
    )
    db.session.add(user)
    db.session.commit()

    # VULN: Weak session - predictable, stored in cookie without secure flags
    session["user_id"] = user.id
    session["username"] = user.username
    session["role"] = user.role

    return jsonify({"message": "Registered successfully", "user": user.to_dict()}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    session["user_id"] = user.id
    session["username"] = user.username
    session["role"] = user.role

    # VULN: JWT with weak secret and no expiration enforcement in middleware
    token = jwt.encode(
        {
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
            "exp": datetime.utcnow() + timedelta(days=365),
        },
        JWT_SECRET,
        algorithm="HS256",
    )

    return jsonify(
        {
            "message": "Login successful",
            "token": token if isinstance(token, str) else token.decode(),
            "user": user.to_dict(),
            "session_id": session.get("user_id"),
        }
    )


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@auth_bp.route("/me", methods=["GET"])
def get_current_user():
    user_id = session.get("user_id") or request.args.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    user = User.query.get(int(user_id))
    if not user:
        return jsonify({"error": "User not found"}), 404

    # VULN: Exposes sensitive fields when debug query param set
    include_sensitive = request.args.get("debug") == "true" or DEBUG
    return jsonify(user.to_dict(include_sensitive=include_sensitive))
