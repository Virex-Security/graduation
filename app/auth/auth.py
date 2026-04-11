"""
Authentication helpers — login / logout with secure access and refresh cookie handling.
"""
import hashlib
import secrets
from datetime import datetime, timedelta

import jwt
from flask import current_app, make_response, request
from app import config
from app.services.auth_service import AuthService
from app.api import responses

def login_user(username: str, password: str):
    """Verify credentials and set tokens in cookies."""
    user = AuthService.verify_credentials(username, password)
    if not user:
        return responses.unauthorized("Invalid credentials")
        
    if user.get("locked"):
        return responses.error("Account is temporarily locked. Please try again in 15 minutes.", status=423) # Locked

    access_token, refresh_token, jti = AuthService.mint_tokens(username, user["role"])

    user_id = user.get("user_id") or user.get("id")
    if user_id:
        ip = request.remote_addr or "unknown"
        ua = request.user_agent.string or ""
        AuthService.register_session(user_id, jti, ip, ua)

    resp_body, status = responses.ok({"message": "Logged in successfully", "role": user["role"]})
    resp = make_response(resp_body)
    is_secure = config.cookie_secure()
    
    resp.set_cookie("auth_token", access_token, httponly=True, secure=is_secure, samesite="Lax", max_age=15 * 60)
    resp.set_cookie("refresh_token", refresh_token, httponly=True, secure=is_secure, samesite="Lax", max_age=7 * 24 * 3600)
    return resp, status


def refresh_user_tokens():
    """Rotate tokens using a valid refresh token."""
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return responses.unauthorized("Refresh token missing")
        
    try:
        data = jwt.decode(refresh_token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        if data.get("type") != "refresh":
            return responses.unauthorized("Invalid token type")
            
        jti = data.get("jti", "")
        if jti and not AuthService.is_session_valid(jti):
            return responses.unauthorized("Session revoked")
            
        username = data.get("user")
        role = data.get("role")
        user = AuthService.get_user(username)
        if not user or user.get("locked"):
            return responses.unauthorized("User invalid or locked")
            
        # Revoke old jti and issue new (Rotation)
        AuthService.revoke_session(jti)
        
        new_access, new_refresh, new_jti = AuthService.mint_tokens(username, role)
        user_id = user.get("user_id") or user.get("id")
        if user_id:
            ip = request.remote_addr or "unknown"
            ua = request.user_agent.string or ""
            AuthService.register_session(user_id, new_jti, ip, ua)
            
        resp_body, status = responses.ok({"message": "Tokens refreshed successfully"})
        resp = make_response(resp_body)
        is_secure = config.cookie_secure()
        
        resp.set_cookie("auth_token", new_access, httponly=True, secure=is_secure, samesite="Lax", max_age=15 * 60)
        resp.set_cookie("refresh_token", new_refresh, httponly=True, secure=is_secure, samesite="Lax", max_age=7 * 24 * 3600)
        return resp, status

    except jwt.ExpiredSignatureError:
        return responses.unauthorized("Refresh token expired")
    except Exception:
        return responses.unauthorized("Invalid refresh token")


def logout_user():
    """Clear cookies and invalidate session."""
    for cookie_name in ["refresh_token", "auth_token"]:
        token = request.cookies.get(cookie_name)
        if token:
            try:
                data = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"], options={"verify_exp": False})
                jti = data.get("jti", "")
                if jti:
                    AuthService.revoke_session(jti)
                    break
            except Exception:
                pass

    resp_body, status = responses.ok({"message": "Logged out successfully"})
    resp = make_response(resp_body)
    is_secure = config.cookie_secure()
    resp.set_cookie("auth_token", "", expires=0, httponly=True, secure=is_secure, samesite="Lax")
    resp.set_cookie("refresh_token", "", expires=0, httponly=True, secure=is_secure, samesite="Lax")
    return resp
