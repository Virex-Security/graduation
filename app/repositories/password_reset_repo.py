from app import database as _db
import time

class PasswordResetRepository:
    """Handles persistence for OTP-based password reset flows."""
    
    @staticmethod
    def create_reset_request(user_id: int, otp_hash: str, expiry_str: str):
        """Creates a new reset request, replacing any existing ones."""
        with _db.db_cursor() as cur:
            cur.execute('DELETE FROM password_resets WHERE user_id = ?', (user_id,))
            cur.execute(
                'INSERT INTO password_resets (user_id, otp, otp_expiry, otp_attempts, used) VALUES (?,?,?,0,0)',
                (user_id, otp_hash, expiry_str)
            )

    @staticmethod
    def get_reset_request(user_id: int):
        with _db.db_cursor() as cur:
            cur.execute('SELECT * FROM password_resets WHERE user_id = ? AND used = 0', (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    @staticmethod
    def mark_as_used(user_id: int):
        with _db.db_cursor() as cur:
            cur.execute('UPDATE password_resets SET used = 1 WHERE user_id = ?', (user_id,))

    @staticmethod
    def increment_attempts(user_id: int):
        with _db.db_cursor() as cur:
            cur.execute('UPDATE password_resets SET otp_attempts = otp_attempts + 1 WHERE user_id = ?', (user_id,))
