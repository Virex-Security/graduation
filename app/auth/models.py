"""
UserManager (DB-backed)
========================
يستخدم SQLite عبر app/database.py بدل JSON file.
نفس الـ API الخارجي محفوظ.
"""
import re
import logging
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app.auth.roles import Role
from app import database as db

logger = logging.getLogger(__name__)


class UserManager:
    """Thread-safe UserManager backed by SQLite."""

    # ── Password Policy ───────────────────────────────────────
    @staticmethod
    def validate_password_policy(password):
        if not isinstance(password, str) or not password:
            return False, "Password is required"
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if not re.search(r"[A-Z]", password):
            return False, "Password must include at least one uppercase letter"
        if not re.search(r"[^A-Za-z0-9]", password):
            return False, "Password must include at least one symbol"
        return True, "Valid password"

    # ── Read ──────────────────────────────────────────────────
    def get_user(self, username: str) -> dict | None:
        user = db.get_user_by_username(username)
        if user:
            user["role"] = user.get("role_name") or user.get("role", "user")
        return user

    def get_user_by_id(self, user_id) -> dict | None:
        user = db.get_user_by_id(user_id)
        if user:
            user["role"] = user.get("role_name") or user.get("role", "user")
        return user

    def get_all_users(self) -> list[dict]:
        return db.get_all_users()

    def verify_password(self, username: str, password: str) -> dict | None:
        user = self.get_user(username)
        if not user:
            return None
            
        # 1. Check Lockout
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
            # Success: Reset attempts
            db.update_user(username, 
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
                # Lock for 15 minutes
                lockout_until = (datetime.now() + timedelta(minutes=15)).isoformat()
                logger.warning(f"[SEC] Account {username} locked due to brute-force attempts.")
            
            db.update_user(username, 
                           failed_login_attempts=attempts,
                           lockout_until=lockout_until)
            return None


    # ── Create ────────────────────────────────────────────────
    def add_user(self, username: str, password: str, role=Role.USER):
        if self.get_user(username):
            return False, "User already exists"
        valid, msg = self.validate_password_policy(password)
        if not valid:
            return False, msg
        try:
            db.insert_user(username, generate_password_hash(password),
                           role=role)
            return True, "User added successfully"
        except Exception as e:
            return False, str(e)

    def create_user(self, username: str, password: str,
                    email=None, role=Role.USER) -> dict:
        if self.get_user(username):
            raise ValueError("User already exists")
        valid, msg = self.validate_password_policy(password)
        if not valid:
            raise ValueError(msg)
        uid = db.insert_user(username, generate_password_hash(password),
                             email=email, role=role)
        return {"id": uid, "username": username, "email": email,
                "role": role, "status": "active"}

    # ── Update ────────────────────────────────────────────────
    def update_user(self, username: str, **kwargs):
        if 'password' in kwargs:
            kwargs['password_hash'] = generate_password_hash(kwargs.pop('password'))
        ok = db.update_user(username, **kwargs)
        return (ok, "Updated" if ok else "User not found")

    def change_password(self, username: str, new_password: str):
        valid, msg = self.validate_password_policy(new_password)
        if not valid:
            return False, msg
        ok = db.update_user(username,
                            password_hash=generate_password_hash(new_password))
        return (ok, "Password changed" if ok else "User not found")

    # ── Delete ────────────────────────────────────────────────
    def delete_user(self, username: str):
        ok = db.delete_user(username)
        return (ok, "Deleted" if ok else "User not found")


# Singleton instance
user_manager = UserManager()
