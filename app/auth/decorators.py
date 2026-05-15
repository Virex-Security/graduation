"""
Auth decorators — login_required, require_role, admin_only, analyst_and_above, manager_and_above.
Injects current_user dict as first arg AND stores in g.current_user.
"""
import hashlib
from functools import wraps

import jwt
from flask import request, jsonify, redirect, url_for, current_app, g

from app.auth.roles import Role


def _is_jti_valid(jti: str) -> bool:
    if not jti:
        return False
    try:
        from app import database as db
        import logging
        logger = logging.getLogger(__name__)
        jti_hash = hashlib.sha256(jti.encode()).hexdigest()
        active = db.is_session_active(jti_hash)
        if not active:
            logger.warning(f"[AUTH] Unknown JTI: {jti_hash}")
            return False
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"[AUTH] DB error verifying JTI: {e}")
        return True


def _build_user_from_token(data):
    return {
        "user_id": data.get("user_id"),
        "username": data.get("username") or data.get("user"),
        "role": data.get("role_name") or data.get("role"),
        "department_id": data.get("department_id"),
        "id": data.get("user_id"),
        "email": data.get("email", ""),
    }


def login_required(f):
    """Verify JWT, inject current_user as first arg, store in g.current_user."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("auth_token")
        if not token:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]

        if not token:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login_page"))

        try:
            data = jwt.decode(
                token,
                current_app.config["SECRET_KEY"],
                algorithms=["HS256"],
            )
            jti = data.get("jti", "")
            if jti and not _is_jti_valid(jti):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Session has been revoked"}), 401
                return redirect(url_for("login_page"))

            current_user = _build_user_from_token(data)
            g.current_user = current_user

        except jwt.ExpiredSignatureError:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Token has expired"}), 401
            return redirect(url_for("login_page"))
        except jwt.InvalidTokenError:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Token is invalid"}), 401
            return redirect(url_for("login_page"))

        return f(current_user, *args, **kwargs)
    return decorated


def require_role(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated(current_user, *args, **kwargs):
            if current_user["role"] not in roles:
                if request.path.startswith("/api/"):
                    return jsonify({
                        "error": "Forbidden",
                        "required_role": " | ".join(roles),
                        "your_role": current_user["role"],
                    }), 403
                return redirect(url_for("forbidden_page"))
            return f(current_user, *args, **kwargs)
        return decorated
    return decorator


def admin_only(f):
    return require_role(Role.ADMIN)(f)


def analyst_and_above(f):
    return require_role(Role.ADMIN, Role.ANALYST)(f)


def manager_and_above(f):
    return require_role(Role.ADMIN, Role.ANALYST, Role.MANAGER, Role.USER)(f)


# ── Backward compatibility aliases ─────────────────────────────
token_required = login_required
admin_required = admin_only
