import json
import os
<<<<<<< HEAD
import re
from pathlib import Path
=======
>>>>>>> 967891135f8e00079cef2ba1d9796462c24daaba
from werkzeug.security import generate_password_hash, check_password_hash
from roles import Role

class UserManager:
<<<<<<< HEAD
    def __init__(self, storage_path=None):
        # Use data/ directory for storage
        if storage_path is None:
            project_root = Path(__file__).parent
            storage_path = project_root / "data" / "users.json"
        self.storage_path = str(storage_path)
=======
    def __init__(self, storage_path="users.json"):
        self.storage_path = storage_path
>>>>>>> 967891135f8e00079cef2ba1d9796462c24daaba
        self.users = {}
        self._load_users()

    def _load_users(self):
        if os.path.exists(self.storage_path):
            with open(self.storage_path, 'r') as f:
                self.users = json.load(f)
        else:
            # Initialize with default users if not exists
<<<<<<< HEAD
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            self.add_user("admin", "Admin@123", Role.ADMIN)
            self.add_user("user", "User@123", Role.USER)
            self._save_users()

    def _save_users(self):
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        with open(self.storage_path, 'w') as f:
            json.dump(self.users, f, indent=4)

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

    def add_user(self, username, password, role=Role.USER):
        if username in self.users:
            return False, "User already exists"

        valid, message = self.validate_password_policy(password)
        if not valid:
            return False, message
=======
            self.add_user("admin", "admin123", Role.ADMIN)
            self.add_user("user", "user123", Role.USER)
            self._save_users()

    def _save_users(self):
        with open(self.storage_path, 'w') as f:
            json.dump(self.users, f, indent=4)

    def add_user(self, username, password, role=Role.USER):
        if username in self.users:
            return False, "User already exists"
>>>>>>> 967891135f8e00079cef2ba1d9796462c24daaba
        
        self.users[username] = {
            "id": len(self.users) + 1,
            "username": username,
            "password_hash": generate_password_hash(password),
            "role": role
        }
        self._save_users()
        return True, "User added successfully"

    def get_user(self, username):
        return self.users.get(username)

    def verify_password(self, username, password):
        user = self.get_user(username)
        if user and check_password_hash(user['password_hash'], password):
            return user
        return None

<<<<<<< HEAD
    def change_password(self, username, new_password):
        if username not in self.users:
            return False, "User not found"

        valid, message = self.validate_password_policy(new_password)
        if not valid:
            return False, message

        self.users[username]["password_hash"] = generate_password_hash(new_password)
        self._save_users()
        return True, "Password changed successfully"

=======
>>>>>>> 967891135f8e00079cef2ba1d9796462c24daaba
# Singleton-like instance
user_manager = UserManager()
