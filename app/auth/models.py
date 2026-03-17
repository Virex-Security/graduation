import json
import os
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
from app.auth.roles import Role

class UserManager:
    def __init__(self, storage_path=None):
        # Use data/ directory for storage
        if storage_path is None:
            project_root = Path(__file__).parent.parent.parent
            storage_path = project_root / "data" / "users.json"
        self.storage_path = str(storage_path)
        self.users = {}
        self._load_users()

    def _load_users(self):
        if os.path.exists(self.storage_path):
            with open(self.storage_path, 'r') as f:
                self.users = json.load(f)
        else:
            # Initialize with default users if not exists
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            self.add_user("admin", "admin123", Role.ADMIN)
            self.add_user("user", "user123", Role.USER)
            self._save_users()

    def _save_users(self):
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        with open(self.storage_path, 'w') as f:
            json.dump(self.users, f, indent=4)

    def add_user(self, username, password, role=Role.USER):
        if username in self.users:
            return False, "User already exists"
        
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

# Singleton-like instance
user_manager = UserManager()
