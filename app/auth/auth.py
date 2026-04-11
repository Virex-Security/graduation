"""
Authentication helpers — login / logout with secure access and refresh cookie handling.
"""
import hashlib
import secrets
from datetime import datetime, timedelta

import jwt
from flask import current_app, make_response, jsonify, request
from app import config
from app.services.auth_service import AuthService

def login_user(username: str, password: str):
    """Verify credentials and set tokens in cookies."""
    user = AuthService.verify_credentials(username, password)
    if not user:
        return jsonify({"message": "Invalid credentials"}), 401
        
    if user.get("locked"):
        return jsonify({
            "status": "error",
            "message": "Account is temporarily locked. Please try again in 15 minutes."
        }), 423 # Locked

    access_token, refresh_token, jti = AuthService.mint_tokens(username, user["role"])

    user_id = user.get("user_id") or user.get("id")
    if user_id:
        ip = request.remote_addr or "unknown"
        ua = request.user_agent.string or ""
        AuthService.register_session(user_id, jti, ip, ua)

    resp = make_response(jsonify({"message": "Logged in successfully", "role": user["role"]}))
    is_secure = config.cookie_secure()
    
    resp.set_cookie("auth_token", access_token, httponly=True, secure=is_secure, samesite="Lax", max_age=15 * 60)
    resp.set_cookie("refresh_token", refresh_token, httponly=True, secure=is_secure, samesite="Lax", max_age=7 * 24 * 3600)
    return resp, 200


def refresh_user_tokens():
    """Rotate tokens using a valid refresh token."""
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return jsonify({"message": "Refresh token missing"}), 401
        
    try:
        data = jwt.decode(refresh_token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        if data.get("type") != "refresh":
            return jsonify({"message": "Invalid token type"}), 401
            
        jti = data.get("jti", "")
        if jti and not AuthService.is_session_valid(jti):
            return jsonify({"message": "Session revoked"}), 401
            
        username = data.get("user")
        role = data.get("role")
        user = AuthService.get_user(username)
        if not user or user.get("locked"):
            return jsonify({"message": "User invalid or locked"}), 401
            
        # Revoke old jti and issue new (Rotation)
        AuthService.revoke_session(jti)
        
        new_access, new_refresh, new_jti = AuthService.mint_tokens(username, role)
        user_id = user.get("user_id") or user.get("id")
        if user_id:
            ip = request.remote_addr or "unknown"
            ua = request.user_agent.string or ""
            AuthService.register_session(user_id, new_jti, ip, ua)
            
        resp = make_response(jsonify({"message": "Tokens refreshed successfully"}))
        is_secure = config.cookie_secure()
        
        resp.set_cookie("auth_token", new_access, httponly=True, secure=is_secure, samesite="Lax", max_age=15 * 60)
        resp.set_cookie("refresh_token", new_refresh, httponly=True, secure=is_secure, samesite="Lax", max_age=7 * 24 * 3600)
        return resp, 200

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Refresh token expired"}), 401
    except Exception:
        return jsonify({"message": "Invalid refresh token"}), 401


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

    resp = make_response(jsonify({"message": "Logged out successfully"}))
    is_secure = config.cookie_secure()
    resp.set_cookie("auth_token", "", expires=0, httponly=True, secure=is_secure, samesite="Lax")
    resp.set_cookie("refresh_token", "", expires=0, httponly=True, secure=is_secure, samesite="Lax")
    return resp
