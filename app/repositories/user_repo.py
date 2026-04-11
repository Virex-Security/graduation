from app import database as db

class UserRepository:
    """Handles raw database access for user entities."""
    
    @staticmethod
    def get_by_username(username: str) -> dict | None:
        return db.get_user_by_username(username)
        
    @staticmethod
    def get_by_id(user_id: int) -> dict | None:
        return db.get_user_by_id(user_id)
        
    @staticmethod
    def get_all() -> list[dict]:
        return db.get_all_users()
        
    @staticmethod
    def create(username: str, password_hash: str, email: str = None, role: str = "user") -> int:
        return db.insert_user(username, password_hash, email=email, role=role)
        
    @staticmethod
    def update(username: str, **kwargs) -> bool:
        return db.update_user(username, **kwargs)
        
    @staticmethod
    def delete(username: str) -> bool:
        return db.delete_user(username)
