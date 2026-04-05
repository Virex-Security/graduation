import secrets
import string
import logging
from datetime import datetime, timedelta
from app import database as db
from app.auth.models import UserManager
from werkzeug.security import generate_password_hash

logger = logging.getLogger(__name__)

RESET_TOKEN_LENGTH = 48
RESET_TOKEN_EXPIRY_MINUTES = 15


def generate_reset_token(length=RESET_TOKEN_LENGTH):
    token = secrets.token_urlsafe(length)
    logger.debug("[RESET] Token generated for user")
    return token


def set_reset_token(email):
    user = db.get_user_by_email(email)
    if not user:
        logger.warning("[RESET] No user found for provided email")
        return None, "User not found"
    token = generate_reset_token()
    expiry = (datetime.utcnow() + timedelta(minutes=RESET_TOKEN_EXPIRY_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
    with db.db_cursor() as cur:
        cur.execute("UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?", (token, expiry, email))
    logger.info("[RESET] Password reset token generated and set for user")
    return token, None


def verify_reset_token(token):
    with db.db_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE reset_token = ?", (token,))
        user = cur.fetchone()
        if not user:
            logger.warning("[RESET] Invalid or malformed token attempt")
            return None, "Invalid token"
        expiry = user["reset_token_expiry"]
        if not expiry or datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S") < datetime.utcnow():
            logger.warning("[RESET] Expired token attempt")
            return None, "Token expired"
        return dict(user), None


def reset_password(token, new_password):
    user, err = verify_reset_token(token)
    if err:
        return False, err
    valid, msg = UserManager.validate_password_policy(new_password)
    if not valid:
        return False, msg
    password_hash = generate_password_hash(new_password)
    with db.db_cursor() as cur:
        cur.execute("UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE user_id = ?", (password_hash, user["user_id"]))
    logger.info("[RESET] Password reset successfully completed")
    return True, None
