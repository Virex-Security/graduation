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


def mint_token(username: str, role_name: str, role_id: int = None, user_id: int = None, department_id: int = None) -> tuple[str, str]:
    """
    Create a signed JWT and return (token, jti).
    Payload includes user_id, role_id, role_name, username, department_id, exp.
    """
    jti = secrets.token_hex(16)
    token = jwt.encode(
        {
            "user_id": user_id,
            "username": username,
            "role_name": role_name,
            "role_id": role_id,
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


