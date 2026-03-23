import json
import os
import re
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

    def update_user(self, username, **kwargs):
        if username in self.users:
            for k, v in kwargs.items():
                if k == 'password':
                    # Hash the password before storing
                    self.users[username]['password_hash'] = generate_password_hash(v)
                else:
                    self.users[username][k] = v
            self._save_users()
            return True, "User updated successfully"
        return False, "User not found"

    def verify_password(self, username, password):
        user = self.get_user(username)
        if user and check_password_hash(user['password_hash'], password):
            return user
        return None

    def change_password(self, username, new_password):
        if username not in self.users:
            return False, "User not found"

        valid, message = self.validate_password_policy(new_password)
        if not valid:
            return False, message

        self.users[username]["password_hash"] = generate_password_hash(new_password)
        self._save_users()
        return True, "Password changed successfully"
    
    def get_all_users(self):
        """Get all users as a list"""
        from datetime import datetime
        users_list = []
        for username, user_data in self.users.items():
            users_list.append({
                'id': user_data.get('id'),
                'user_id': user_data.get('id'),
                'username': username,
                'email': user_data.get('email', f'{username}@example.com'),
                'full_name': user_data.get('full_name', username),
                'role': user_data.get('role', Role.USER),
                'status': user_data.get('status', 'active'),
                'account_status': user_data.get('status', 'active'),
                'created_at': user_data.get('created_at', datetime.now().isoformat()),
                'last_login': user_data.get('last_login'),
            })
        return users_list
    
    def get_user_by_id(self, user_id):
        """Get user by ID"""
        for username, user_data in self.users.items():
            if str(user_data.get('id')) == str(user_id):
                return {
                    'id': user_data.get('id'),
                    'user_id': user_data.get('id'),
                    'username': username,
                    'email': user_data.get('email', f'{username}@example.com'),
                    'full_name': user_data.get('full_name', username),
                    'role': user_data.get('role', Role.USER),
                    'status': user_data.get('status', 'active'),
                    'account_status': user_data.get('status', 'active'),
                    'created_at': user_data.get('created_at'),
                    'last_login': user_data.get('last_login'),
                }
        return None
    
    def delete_user(self, username):
        """Delete a user by username"""
        if username not in self.users:
            return False, "User not found"
        del self.users[username]
        self._save_users()
        return True, "User deleted successfully"

    def create_user(self, username, password, email=None, role=Role.USER):
        """Create a new user"""
        from datetime import datetime
        
        if username in self.users:
            raise ValueError("User already exists")
        
        valid, message = self.validate_password_policy(password)
        if not valid:
            raise ValueError(message)
        
        user_id = max([u.get('id', 0) for u in self.users.values()], default=0) + 1
        
        self.users[username] = {
            "id": user_id,
            "username": username,
            "password_hash": generate_password_hash(password),
            "email": email or f'{username}@example.com',
            "full_name": username,
            "role": role,
            "status": "active",
            "created_at": datetime.now().isoformat(),
        }
        self._save_users()
        
        return {
            'id': user_id,
            'user_id': user_id,
            'username': username,
            'email': email or f'{username}@example.com',
            'role': role,
            'status': 'active',
        }

# Singleton-like instance
user_manager = UserManager()
