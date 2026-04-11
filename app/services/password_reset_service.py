import secrets
import bcrypt
import time
import logging
import smtplib
import os
from email.mime.text import MIMEText
from app.repositories.password_reset_repo import PasswordResetRepository
from app.repositories.user_repo import UserRepository
from app import config as _cfg

logger = logging.getLogger(__name__)

class PasswordResetService:
    """Business logic for password reset flows via OTP."""
    
    @staticmethod
    def initiate_reset(identifier: str) -> tuple[bool, str]:
        """Validates user and sends OTP email if user exists."""
        # identifier can be username or email
        user = UserRepository.get_by_username(identifier)
        if not user:
            # Check by email
            all_users = UserRepository.get_all()
            user = next((u for u in all_users if u.get('email','').lower() == identifier.lower()), None)
            
        if not user:
            # Standard security practice: return success even if user not found to prevent enumeration
            return True, "If that email is registered, a reset link was sent."
            
        user_id = user.get('user_id') or user.get('id')
        email = user.get('email')
        if not email:
            return True, "If that email is registered, a reset link was sent."
            
        # Generate OTP
        otp = secrets.token_urlsafe(16)
        otp_hash = bcrypt.hashpw(otp.encode(), bcrypt.gensalt()).decode()
        expiry = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 300))
        
        PasswordResetRepository.create_reset_request(user_id, otp_hash, expiry)
        
        # Send Email
        success = PasswordResetService._send_email(email, otp)
        if not success:
            return False, "Failed to send reset email. Contact support."
            
        return True, "Success"

    @staticmethod
    def verify_and_reset(identifier, otp, new_password) -> tuple[bool, str]:
        """Verifies OTP and updates user password."""
        user = UserRepository.get_by_username(identifier)
        if not user:
            # Check by email
            all_users = UserRepository.get_all()
            user = next((u for u in all_users if u.get('email','').lower() == identifier.lower()), None)
            
        if not user:
            return False, "User not found"
            
        user_id = user.get('user_id') or user.get('id')
        reset_req = PasswordResetRepository.get_reset_request(user_id)
        
        if not reset_req:
            return False, "No active reset request found"
            
        if reset_req.get('otp_attempts', 0) >= 3:
            return False, "Too many attempts. Request a new code."
            
        # Check expiry
        try:
            expiry_ts = time.mktime(time.strptime(reset_req['otp_expiry'], '%Y-%m-%d %H:%M:%S'))
            if time.time() > expiry_ts:
                return False, "OTP has expired"
        except Exception:
            return False, "Invalid expiry format"
            
        # Verify hash
        if not bcrypt.checkpw(otp.encode(), reset_req['otp'].encode()):
            PasswordResetRepository.increment_attempts(user_id)
            return False, "Invalid OTP code"
            
        # Success - Change Password
        from werkzeug.security import generate_password_hash
        UserRepository.update(user['username'], password_hash=generate_password_hash(new_password))
        PasswordResetRepository.mark_as_used(user_id)
        
        return True, "Password reset successfully"

    @staticmethod
    def _send_email(to_email, otp):
        """Hidden helper for SMTP logic."""
        sender = os.getenv('SMTP_EMAIL')
        pwd = _cfg.smtp_password()
        if not sender or not pwd:
            logger.error("SMTP credentials missing!")
            return False
            
        try:
            msg = MIMEText(f"Your OTP for password reset is: {otp}\nExpires in 5 minutes.")
            msg['Subject'] = "Password Reset OTP"
            msg['From'] = f"Virex Security <{sender}>"
            msg['To'] = to_email
            
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(sender, pwd)
                server.send_message(msg)
            return True
        except Exception as e:
            logger.error(f"SMTP Error: {e}")
            return False
