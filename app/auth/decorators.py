"""
Auth decorators — token_required, require_role, admin_required.
Now validates jti against the session store to support logout revocation.
"""
import hashlib
<<<<<<< HEAD
=======
<<<<<<< HEAD
=======
import sqlite3
import logging
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
from functools import wraps

import jwt
from flask import request, jsonify, redirect, url_for, current_app

from app.auth.roles import Role
from app.auth.models import user_manager


def _is_jti_valid(jti: str) -> bool:
    """
    Check whether the token's jti exists and is still active in user_sessions.
    Returns False if a session row does not exist to prevent replay of revoked or rogue tokens.
    """
    if not jti:
        return False
    try:
        from app import database as db
        import logging
        logger = logging.getLogger(__name__)
        
        jti_hash = hashlib.sha256(jti.encode()).hexdigest()
        with db.db_cursor() as cur:
            cur.execute(
                "SELECT is_active FROM user_sessions WHERE jwt_token_hash = ?",
                (jti_hash,)
            )
            row = cur.fetchone()
            
        if row is None:
            logger.warning(f"[AUTH] Unknown or deleted JTI encountered: {jti_hash}. Rejecting token to prevent replay.")
            return False
            
        return bool(row["is_active"])
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    except Exception as e:
        # If DB check fails (e.g., table missing/locked, operational error), default to True.
        # Trade-off: This is an acceptable availability-over-security risk 
        # to ensure legitimate users aren't globally locked out during transient DB hiccups.
        import logging
        logging.getLogger(__name__).error(f"[AUTH] DB error verifying JTI: {e}. Allowing token by default.")
        return True
<<<<<<< HEAD
=======
=======
    except sqlite3.OperationalError:
        # Transient DB error (locked, busy timeout) — Fail-Open for availability
        logging.getLogger(__name__).warning("[AUTH] Transient DB error on JTI check — allowing token.")
        return True
    except Exception:
        # Unexpected error (schema issue, attribute error, etc.) — Fail-Closed for security.
        # Use exc_info=False to prevent leaking sensitive file paths or stack traces in logs.
        logging.getLogger(__name__).error("[AUTH] Unexpected JTI verification error — denying access.", exc_info=False)
        return False
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578


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
