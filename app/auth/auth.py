"""
Authentication helpers — login / logout with secure cookie handling.
"""
import hashlib
import secrets
from datetime import datetime, timedelta

import jwt
from flask import current_app, make_response, jsonify, request

from app.auth.models import user_manager
from app import config


def _mint_token(username: str, role: str) -> tuple[str, str]:
    """
    Create a signed JWT and return (token, jti).
    The jti (JWT ID) is used for revocation.
    """
    jti = secrets.token_hex(16)
    token = jwt.encode(
        {
            "user": username,
            "role": role,
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
        
    if user.get("locked"):
        return jsonify({
            "status": "error",
            "message": "Account is temporarily locked. Please try again in 15 minutes."
        }), 423 # Locked


    token, jti = _mint_token(username, user["role"])

    # Persist jti for revocation support
    user_id = user.get("user_id") or user.get("id")
    if user_id:
        _register_session(user_id, jti)

    resp = make_response(
        jsonify({"message": "Logged in successfully", "role": user["role"]})
    )
    resp.set_cookie(
        "auth_token",
        token,
        httponly=True,
        secure=config.cookie_secure(),   # ← env-driven, not hardcoded False
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
                options={"verify_exp": False},   # still process expired tokens on logout
            )
            jti = data.get("jti", "")
            if jti:
                from app import database as db
                jti_hash = hashlib.sha256(jti.encode()).hexdigest()
                db.invalidate_session(jti_hash)
        except Exception:
            pass  # always clear the cookie regardless

    resp = make_response(jsonify({"message": "Logged out successfully"}))
    resp.set_cookie("auth_token", "", expires=0, httponly=True,
                    secure=config.cookie_secure(), samesite="Lax")
    return resp
