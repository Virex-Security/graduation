import time
from app import database as db

class ThreatRepository:
    """Abstractions for threat logs, blocked IPs, and incident management."""
    
    @staticmethod
    def log_threat(attack_type: str, ip_address: str, endpoint: str,
                   method: str, payload: str = "", severity: str = "Medium",
                   description: str = "", blocked: bool = False,
                   ml_detected: bool = False, confidence: float = 0.0,
                   detection_type: str = "rule") -> int:
        return db.log_threat(
            attack_type=attack_type,
            ip_address=ip_address,
            endpoint=endpoint,
            method=method,
            payload=payload,
            severity=severity,
            description=description,
            blocked=blocked,
            ml_detected=ml_detected,
            confidence=confidence,
            detection_type=detection_type
        )

    @staticmethod
    def get_logs(limit: int = 100, attack_type: str = None, severity: str = None) -> list:
        return db.get_threat_logs(limit, attack_type, severity)

    @staticmethod
    def get_stats() -> dict:
        return db.load_stats()

    @staticmethod
    def get_blocked_ips() -> dict:
        return db.load_blocked_ips()

    @staticmethod
    def block_ip(ip: str, duration_seconds: int = 3600, reason: str = "auto-block",
                 blocked_by: int = None, is_permanent: bool = False):
        unblock_at_ts = time.time() + duration_seconds
        db.block_ip(ip, unblock_at_ts, reason, blocked_by, is_permanent)

    @staticmethod
    def unblock_ip(ip: str):
        db.unblock_ip(ip)

    @staticmethod
    def log_blocked_event(ip_address: str, attack_type: str, severity: str,
                          ml_detected: bool = False, confidence: float = 0.0,
                          threat_log_id: int = None):
        db.log_blocked_event(ip_address, attack_type, severity, ml_detected, confidence, threat_log_id)

    @staticmethod
    def get_blocked_events(limit: int = 100) -> list:
        return db.get_blocked_events(limit)

    @staticmethod
    def create_incident(category: str, source_ip: str, severity: str,
                        detection_type: str = "rule") -> int:
        return db.create_incident(category, source_ip, severity, detection_type)

    @staticmethod
    def get_incidents(status: str = None, limit: int = 100) -> list:
        return db.get_incidents(status, limit)

    @staticmethod
    def update_incident_status(incident_id: int, new_status: str,
                                actor_id: int = None, comment: str = ""):
        return db.update_incident_status(incident_id, new_status, actor_id, comment)

    @staticmethod
    def clear_all() -> bool:
        db.clear_all_attacks()
        return True
