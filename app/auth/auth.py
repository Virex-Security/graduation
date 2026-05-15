"""
Authentication helpers — login / logout with secure cookie handling.
JWT payload includes user_id, username, role_name, department_id, exp.
"""
import hashlib
import secrets
from datetime import datetime, timedelta

import jwt
from flask import current_app, make_response, jsonify, request

from app.auth.models import user_manager
from app import config


def _mint_token(username: str, role: str, user_id: int = None, department_id: int = None) -> tuple[str, str]:
    """
    Create a signed JWT and return (token, jti).
    Payload includes user_id, username, role_name, department_id, exp.
    """
    jti = secrets.token_hex(16)
    token = jwt.encode(
        {
            "user_id": user_id,
            "username": username,
            "role_name": role,
            "department_id": department_id,
            "exp": datetime.utcnow() + timedelta(hours=8),
            "iat": datetime.utcnow(),
            "jti": jti,
        },
        current_app.config["SECRET_KEY"],
        algorithm="HS256",
    )
    return token, jti


def _register_session(user_id: int, jti: str) -> None:
    """Persist the jti in user_sessions so it can be revoked."""
    try:
        from app import database as db
        jti_hash = hashlib.sha256(jti.encode()).hexdigest()
        expires_at = (datetime.utcnow() + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")
        ip = request.remote_addr or "unknown"
        ua = request.user_agent.string or ""
        db.create_session(user_id, jti_hash, ip, ua, expires_at)
    except Exception:
        pass  # session persistence failure must not block login


def login_user(username: str, password: str):
    """Verify credentials, mint token, set httpOnly cookie."""
    user = user_manager.verify_password(username, password)
    if not user:
        return jsonify({"message": "Invalid credentials"}), 401

    user_id = user.get("user_id") or user.get("id")
    role = user.get("role_name") or user.get("role", "user")
    department_id = user.get("department_id")

    token, jti = _mint_token(username, role, user_id, department_id)

    if user_id:
        _register_session(user_id, jti)

    resp = make_response(
        jsonify({"message": "Logged in successfully", "role": role})
    )
    resp.set_cookie(
        "auth_token",
        token,
        httponly=True,
        secure=config.cookie_secure(),
        samesite="Lax",
        max_age=8 * 3600,
    )
    return resp, 200


def logout_user():
    """Clear auth cookie and invalidate the server-side session."""
    token = request.cookies.get("auth_token")
    if token:
        try:
            data = jwt.decode(
                token,
                current_app.config["SECRET_KEY"],
                algorithms=["HS256"],
                options={"verify_exp": False},
            )
            jti = data.get("jti", "")
            if jti:
                from app import database as db
                jti_hash = hashlib.sha256(jti.encode()).hexdigest()
                db.invalidate_session(jti_hash)
        except Exception:
            pass

    resp = make_response(jsonify({"message": "Logged out successfully"}))
    resp.set_cookie("auth_token", "", expires=0, httponly=True,
                    secure=config.cookie_secure(), samesite="Lax")
    return resp
