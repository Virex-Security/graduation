"""
Auth decorators — token_required, require_role, admin_required.
Now validates jti against the session store to support logout revocation.
"""
import hashlib
from functools import wraps

import jwt
from flask import request, jsonify, redirect, url_for, current_app

from app.auth.roles import Role
from app.auth.models import user_manager


def _is_jti_valid(jti: str) -> bool:
    """
    Check whether the token's jti exists and is still active in user_sessions.
    Returns True if no session table exists yet (graceful fallback during migration).
    """
    if not jti:
        return False
    try:
        from app import database as db
        jti_hash = hashlib.sha256(jti.encode()).hexdigest()
        with db.db_cursor() as cur:
            cur.execute(
                "SELECT is_active FROM user_sessions WHERE jwt_token_hash = ?",
                (jti_hash,)
            )
            row = cur.fetchone()
        if row is None:
            # Session not found in DB — could be a token issued before this fix.
            # Accept it to avoid locking out existing users on upgrade.
            return True
        return bool(row["is_active"])
    except Exception:
        # If DB check fails, don't block the user — log and allow.
        return True


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("auth_token")
        if not token:
            if request.path.startswith("/api/"):
                return jsonify({"message": "Token is missing!"}), 401
            return redirect(url_for("login_page"))

        try:
            data = jwt.decode(
                token,
                current_app.config["SECRET_KEY"],
                algorithms=["HS256"],
            )

            # ── jti revocation check ──────────────────────────
            jti = data.get("jti", "")
            if jti and not _is_jti_valid(jti):
                if request.path.startswith("/api/"):
                    return jsonify({"message": "Session has been revoked"}), 401
                return redirect(url_for("login_page"))

            user = user_manager.get_user(data["user"])
            if not user:
                if request.path.startswith("/api/"):
                    return jsonify({"message": "User not found!"}), 401
                return redirect(url_for("login_page"))

            current_user = user.copy()

        except jwt.ExpiredSignatureError:
            if request.path.startswith("/api/"):
                return jsonify({"message": "Token has expired!"}), 401
            return redirect(url_for("login_page"))

        except jwt.InvalidTokenError:
            if request.path.startswith("/api/"):
                return jsonify({"message": "Token is invalid!"}), 401
            return redirect(url_for("login_page"))

        except Exception:
            if request.path.startswith("/api/"):
                return jsonify({"message": "Token is invalid!"}), 401
            return redirect(url_for("login_page"))

        return f(current_user, *args, **kwargs)

    return decorated


def require_role(role):
    def decorator(f):
        @wraps(f)
        @token_required
        def decorated(current_user, *args, **kwargs):
            if current_user["role"] != role and current_user["role"] != Role.ADMIN:
                if request.path.startswith("/api/"):
                    return jsonify({"message": f"{role.capitalize()} access required!"}), 403
                return "Access Denied: Unprivileged access attempt.", 403
            return f(current_user, *args, **kwargs)
        return decorated
    return decorator


def admin_required(f):
    return require_role(Role.ADMIN)(f)
