from app.repositories.audit_repo import AuditRepository

class AuditService:
    """Business logic for audit logging."""
    
    @staticmethod
    def log_action(user_id, action, resource, resource_id=None, details=None, ip=None, ua=None):
        AuditRepository.log(user_id, action, resource, resource_id, details, ip, ua)
        
    @staticmethod
    def get_recent_audit(limit=100):
        return AuditRepository.get_logs(limit=limit)
