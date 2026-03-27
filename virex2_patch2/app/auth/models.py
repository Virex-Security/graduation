import json
import os
import re
import threading
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app.auth.roles import Role


class UserManager:
    """
    ✅ FIX: Thread-safe UserManager with file locking.
    يستخدم threading.Lock + atomic write (write-to-temp then rename)
    لمنع race conditions عند concurrent registrations.
    """

    def __init__(self, storage_path=None):
        if storage_path is None:
            project_root = Path(__file__).parent.parent.parent
            storage_path = project_root / "data" / "users.json"
        self.storage_path = str(storage_path)
        self.users        = {}
        self._lock        = threading.Lock()   # ✅ File-level lock
        self._load_users()

    def _load_users(self):
        with self._lock:
            if os.path.exists(self.storage_path):
                with open(self.storage_path, 'r', encoding='utf-8') as f:
                    self.users = json.load(f)
            else:
                os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
                self._add_user_unsafe("admin", "Admin@123", Role.ADMIN)
                self._add_user_unsafe("user",  "User@123",  Role.USER)
                self._save_users_unsafe()

    def _save_users_unsafe(self):
        """
        Atomic write: يكتب في temp file ثم يعمل rename.
        يضمن عدم تلف الملف لو حصل crash أثناء الكتابة.
        """
        dir_path = os.path.dirname(self.storage_path)
        os.makedirs(dir_path, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(self.users, f, indent=4, ensure_ascii=False)
            shutil.move(tmp_path, self.storage_path)
        except Exception:
            os.unlink(tmp_path)
            raise

    def _save_users(self):
        with self._lock:
            self._save_users_unsafe()

    # ── Password Policy ────────────────────────────────────────
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

    # ── Internal (called while lock is already held) ───────────
    def _add_user_unsafe(self, username, password, role=Role.USER):
        valid, message = self.validate_password_policy(password)
        if not valid:
            return False, message
        self.users[username] = {
            "id":            len(self.users) + 1,
            "username":      username,
            "password_hash": generate_password_hash(password),
            "role":          role,
            "subscription":  "ENTERPRISE",
            "created_at":    datetime.now().isoformat(),
        }
        return True, "User added successfully"

    # ── Public API ─────────────────────────────────────────────
    def add_user(self, username, password, role=Role.USER):
        with self._lock:
            if username in self.users:
                return False, "User already exists"
            ok, msg = self._add_user_unsafe(username, password, role)
            if ok:
                self._save_users_unsafe()
            return ok, msg

    def get_user(self, username):
        with self._lock:
            return self.users.get(username)

    def update_user(self, username, **kwargs):
        with self._lock:
            if username not in self.users:
                return False, "User not found"
            for k, v in kwargs.items():
                if k == 'password':
                    self.users[username]['password_hash'] = generate_password_hash(v)
                else:
                    self.users[username][k] = v
            self._save_users_unsafe()
            return True, "User updated successfully"

    def verify_password(self, username, password):
        user = self.get_user(username)
        if user and check_password_hash(user['password_hash'], password):
            return user
        return None

    def change_password(self, username, new_password):
        valid, message = self.validate_password_policy(new_password)
        if not valid:
            return False, message
        with self._lock:
            if username not in self.users:
                return False, "User not found"
            self.users[username]["password_hash"] = generate_password_hash(new_password)
            self._save_users_unsafe()
        return True, "Password changed successfully"

    def get_all_users(self):
        with self._lock:
            users_snapshot = dict(self.users)
        result = []
        for username, user_data in users_snapshot.items():
            result.append({
                'id':             user_data.get('id'),
                'user_id':        user_data.get('id'),
                'username':       username,
                'email':          user_data.get('email', f'{username}@example.com'),
                'full_name':      user_data.get('full_name', username),
                'role':           user_data.get('role', Role.USER),
                'status':         user_data.get('status', 'active'),
                'account_status': user_data.get('status', 'active'),
                'subscription':   user_data.get('subscription', 'ENTERPRISE'),
                'created_at':     user_data.get('created_at', datetime.now().isoformat()),
                'last_login':     user_data.get('last_login'),
            })
        return result

    def get_user_by_id(self, user_id):
        with self._lock:
            for username, user_data in self.users.items():
                if str(user_data.get('id')) == str(user_id):
                    return {
                        'id':             user_data.get('id'),
                        'user_id':        user_data.get('id'),
                        'username':       username,
                        'email':          user_data.get('email', f'{username}@example.com'),
                        'full_name':      user_data.get('full_name', username),
                        'role':           user_data.get('role', Role.USER),
                        'status':         user_data.get('status', 'active'),
                        'account_status': user_data.get('status', 'active'),
                        'subscription':   user_data.get('subscription', 'ENTERPRISE'),
                        'created_at':     user_data.get('created_at'),
                        'last_login':     user_data.get('last_login'),
                    }
        return None

    def delete_user(self, username):
        with self._lock:
            if username not in self.users:
                return False, "User not found"
            del self.users[username]
            self._save_users_unsafe()
        return True, "User deleted successfully"

    def create_user(self, username, password, email=None, role=Role.USER):
        with self._lock:
            if username in self.users:
                raise ValueError("User already exists")
            valid, message = self.validate_password_policy(password)
            if not valid:
                raise ValueError(message)
            user_id = max((u.get('id', 0) for u in self.users.values()), default=0) + 1
            self.users[username] = {
                "id":            user_id,
                "username":      username,
                "password_hash": generate_password_hash(password),
                "email":         email or f'{username}@example.com',
                "full_name":     username,
                "role":          role,
                "status":        "active",
                "subscription":  "ENTERPRISE",
                "created_at":    datetime.now().isoformat(),
            }
            self._save_users_unsafe()
        return {
            'id':           user_id,
            'user_id':      user_id,
            'username':     username,
            'email':        email or f'{username}@example.com',
            'role':         role,
            'status':       'active',
            'subscription': 'ENTERPRISE',
        }


# Singleton instance
user_manager = UserManager()
