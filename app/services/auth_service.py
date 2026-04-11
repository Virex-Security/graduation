import logging
import re
import secrets
from datetime import datetime, timedelta
import jwt
from flask import current_app
from werkzeug.security import generate_password_hash, check_password_hash

from app.repositories.user_repo import UserRepository
from app.repositories.auth_repo import AuthRepository
from app.auth.roles import Role

logger = logging.getLogger(__name__)

class AuthService:
    """Handles business logic for authentication, tokens, and password policies."""
    
    # ── Password Policy Business Rule ────────────────────────
    @staticmethod
    def validate_password_policy(password: str) -> tuple[bool, str]:
        if not isinstance(password, str) or not password:
            return False, "Password is required"
        if len(password) < 10:
            return False, "Password must be at least 10 characters"
        if not re.search(r"[A-Z]", password):
            return False, "Password must include at least one uppercase letter"
        if not re.search(r"[a-z]", password):
            return False, "Password must include at least one lowercase letter"
        if not re.search(r"[0-9]", password):
            return False, "Password must include at least one number"
        if not re.search(r"[^A-Za-z0-9]", password):
            return False, "Password must include at least one special character (e.g. !@#$%)"
        return True, "Valid password"

    # ── Identity ─────────────────────────────────────────────
    @staticmethod
    def get_user(username: str) -> dict | None:
        user = UserRepository.get_by_username(username)
        if user:
            user["role"] = user.get("role_name") or user.get("role", "user")
        return user

    # ── Login & Lockout Business Logic ───────────────────────
    @staticmethod
    def verify_credentials(username: str, password: str) -> dict | None:
        user = AuthService.get_user(username)
        if not user:
            return None
            
        # 1. Check Lockout Rule
        lockout_str = user.get("lockout_until")
        if lockout_str:
            try:
                lockout_until = datetime.fromisoformat(lockout_str)
                if datetime.now() < lockout_until:
                    user["locked"] = True
                    return user # Return user with locked flag
            except Exception:
                pass
        
        # 2. Verify Password
        if check_password_hash(user["password_hash"], password):
            # Success: Reset attempts via repo
            UserRepository.update(username, 
                               last_login=datetime.now().isoformat(),
                               failed_login_attempts=0,
                               lockout_until=None)
            user["role"] = user.get("role_name") or user.get("role", "user")
            user["locked"] = False
            return user
        else:
            # Failure: Increment attempts
            attempts = user.get("failed_login_attempts", 0) + 1
            lockout_until = None
            if attempts >= 5:
                # Lock for 15 minutes Rule
                lockout_until = (datetime.now() + timedelta(minutes=15)).isoformat()
                logger.warning(f"[SEC] Account {username} locked due to brute-force attempts.")
            
            UserRepository.update(username, 
                               failed_login_attempts=attempts,
                               lockout_until=lockout_until)
            return None

    # ── Tokens Management ────────────────────────────────────
    @staticmethod
    def mint_tokens(username: str, role: str) -> tuple[str, str, str]:
        """Create signed access and refresh JWTs."""
        jti = secrets.token_hex(16)
        
        access_token = jwt.encode(
            {"user": username, "role": role, "type": "access",
             "exp": datetime.utcnow() + timedelta(minutes=15),
             "iat": datetime.utcnow(), "jti": jti},
            current_app.config["SECRET_KEY"], algorithm="HS256"
        )
        
        refresh_token = jwt.encode(
            {"user": username, "role": role, "type": "refresh",
             "exp": datetime.utcnow() + timedelta(days=7),
             "iat": datetime.utcnow(), "jti": jti},
            current_app.config["SECRET_KEY"], algorithm="HS256"
        )
        return access_token, refresh_token, jti

    @staticmethod
    def register_session(user_id: int, jti: str, ip: str, ua: str) -> bool:
        return AuthRepository.create_session(user_id, jti, ip, ua)

    @staticmethod
    def revoke_session(jti: str) -> bool:
        return AuthRepository.invalidate_session(jti)
        
    @staticmethod
    def verify_credentials_and_generate_response(username, password):
        """Verifies credentials and returns (Flask Response, status_code)."""
        from flask import make_response, request
        from app import config
        from app.api import responses
        
        user = AuthService.verify_credentials(username, password)
        if not user:
            return responses.unauthorized("Invalid credentials")
            
        if user.get("locked"):
            # 423 Locked
            return responses.error("Account is temporarily locked. Please try again in 15 minutes.", status=423)
            
        access_token, refresh_token, jti = AuthService.mint_tokens(username, user["role"])
        
        user_id = user.get("user_id") or user.get("id")
        if user_id:
            ip = request.remote_addr or "unknown"
            ua = request.user_agent.string or ""
            AuthService.register_session(user_id, jti, ip, ua)
            
        resp_body, status = responses.ok({"message": "Logged in successfully", "role": user["role"]})
        resp = make_response(resp_body)
        is_secure = config.cookie_secure()
        
        resp.set_cookie("auth_token", access_token, httponly=True, secure=is_secure, samesite="Lax", max_age=15 * 60)
        resp.set_cookie("refresh_token", refresh_token, httponly=True, secure=is_secure, samesite="Lax", max_age=7 * 24 * 3600)
        return resp, status
