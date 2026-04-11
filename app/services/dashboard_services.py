import logging
from app.repositories.threat_repo import ThreatRepository
from app.repositories.audit_repo import AuditRepository

logger = logging.getLogger(__name__)

class AnalyticsService:
    """Business logic for security analytics and reporting."""
    
    @staticmethod
    def get_stats():
        return ThreatRepository.get_stats()
    
    @staticmethod
    def reset_all_data():
        """Aggregated reset for stats, threats, and audit logs."""
        ThreatRepository.clear_all()
        # AuditRepository.clear_all() - If we want to clear audit logs too
        return True

class IncidentService:
    """Coordination logic for incident life-cycle (Analyze, Block, Close)."""
    
    @staticmethod
    def perform_action(incident_id, action, actor, comment=""):
        # This would eventually interact with an IncidentRepository
        # For now, we can log the action in the audit log
        from app.services.audit_service import AuditService
        AuditService.log_action(None, f"Incident_{action.upper()}", f"Incident: {incident_id}", details=comment)
        return True, "Action recorded"
