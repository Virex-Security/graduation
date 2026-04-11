from app import database as db

class AuditRepository:
    """Handles persistence for audit logs."""
    
    @staticmethod
    def log(user_id: int, action: str, resource: str,
            resource_id: str = None, details: str = None,
            ip_address: str = None, user_agent: str = None):
        db.log_audit(user_id, action, resource, resource_id, details, ip_address, user_agent)
        
    @staticmethod
    def get_logs(user_id: int = None, limit: int = 100) -> list:
        return db.get_audit_logs(user_id, limit)
