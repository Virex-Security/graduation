import re
from werkzeug.security import generate_password_hash, check_password_hash
from roles import Role
from app.db_helpers import (
    get_user_by_username, insert_user, update_user, delete_user
)


class UserManager:

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
        if get_user_by_username(username):
            return False, "User already exists"

        valid, message = self.validate_password_policy(password)
        if not valid:
            return False, message

        password_hash = generate_password_hash(password)
        insert_user(username, password_hash, role=role)
        return True, "User added successfully"

    def get_user(self, username):
        """
        بيجيب المستخدم من الـ database وبيضيف مفتاح 'role'
        من role_name عشان باقي الكود يشتغل بدون تغيير.
        """
        user = get_user_by_username(username)
        if user and 'role' not in user:
            # role_name بييجي من الـ JOIN مع جدول roles
            user['role'] = user.get('role_name', Role.USER)
        return user

    def verify_password(self, username, password):
        user = self.get_user(username)
        if user and check_password_hash(user['password_hash'], password):
            return user
        return None

    def change_password(self, username, new_password):
        user = self.get_user(username)
        if not user:
            return False, "User not found"

        valid, message = self.validate_password_policy(new_password)
        if not valid:
            return False, message

        password_hash = generate_password_hash(new_password)
        update_user(username, password_hash=password_hash)
        return True, "Password changed successfully"


# Singleton-like instance
user_manager = UserManager()