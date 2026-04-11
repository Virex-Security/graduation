from app import database as db

class RuleRepository:
    """Handles persistence for WAF security rules."""
    
    @staticmethod
    def get_all(active_only: bool = True) -> list:
        return db.get_rules(active_only)
    
    @staticmethod
    def ensure_default_rules():
        db._seed_rules_table()
