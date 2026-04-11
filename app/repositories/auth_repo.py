import hashlib
from datetime import datetime, timedelta
from app import database as db

class AuthRepository:
    @staticmethod
    def create_session(user_id: int, jti: str, ip: str, ua: str) -> bool:
        """Persist a refresh session in the database."""
        try:
            jti_hash = hashlib.sha256(jti.encode()).hexdigest()
            expires_at = (datetime.utcnow() + timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
            db.create_session(user_id, jti_hash, ip, ua, expires_at)
            return True
        except Exception:
            return False

    @staticmethod
    def invalidate_session(jti: str) -> bool:
        """Revoke a session by JWT ID."""
        try:
            if jti:
                jti_hash = hashlib.sha256(jti.encode()).hexdigest()
                db.invalidate_session(jti_hash)
            return True
        except Exception:
            return False
            
    @staticmethod
    def is_session_valid(jti: str) -> bool:
        """Check if a session is currently active (not revoked/expired)."""
        if not jti:
            return False
        jti_hash = hashlib.sha256(jti.encode()).hexdigest()
        session = db.get_user_session(jti_hash)
        if not session:
            return False
            
        expires_at_str = session.get('expires_at')
        if expires_at_str:
            try:
                expires_at = datetime.strptime(expires_at_str, "%Y-%m-%d %H:%M:%S")
                if datetime.utcnow() > expires_at:
                    return False
            except ValueError:
                return False
        
        return not session.get('revoked', 0)
