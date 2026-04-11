import logging
import re
from app.repositories.user_repo import UserRepository
from app.auth.roles import Role
from app.services.auth_service import AuthService

logger = logging.getLogger(__name__)

class UserService:
    """Business logic for user management and registration."""
    
    @staticmethod
    def register_user(username, password, full_name=None, email=None, phone=None, department=None, role=Role.USER):
        """Standardizes user registration flow with validation and policy enforcement."""
        # 1. Existence Check
        if UserRepository.get_by_username(username):
            return False, "Username already exists"
            
        # 2. Policy Validation
        is_valid, msg = AuthService.validate_password_policy(password)
        if not is_valid:
            return False, msg
            
        # 3. Create User (Repository handles hashing vs DB columns depending on implementation)
        from werkzeug.security import generate_password_hash
        password_hash = generate_password_hash(password)
        
        try:
            user_id = UserRepository.create(
                username=username,
                password_hash=password_hash,
                email=email,
                role=role
            )
            
            # 4. Update extended fields if provided
            if full_name or phone or department:
                UserRepository.update(
                    username,
                    full_name=full_name,
                    phone=phone,
                    department=department
                )
                
            return True, "User registered successfully"
        except Exception as e:
            logger.error(f"Failed to register user: {e}")
            return False, str(e)

    @staticmethod
    def get_user_details(username):
        return UserRepository.get_by_username(username)

    @staticmethod
    def update_profile(username, **kwargs):
        # Filter allowed profile fields
        allowed = {"full_name", "phone", "department", "email"}
        filtered = {k: v for k, v in kwargs.items() if k in allowed}
        return UserRepository.update(username, **filtered)
