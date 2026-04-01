from datetime import datetime, timedelta
import jwt
from flask import current_app, make_response, jsonify
from app.auth.models import user_manager
from app.auth.roles import Role
import secrets
def login_user(username, password):
    user = user_manager.verify_password(username, password)
    if user:
        token = jwt.encode({
            'user': username,
            'role': user['role'],
            'exp': datetime.utcnow() + timedelta(hours=8),
            'jti': secrets.token_hex(16),
        }, current_app.config['SECRET_KEY'], algorithm="HS256")

        resp = make_response(jsonify({
            'message': 'Logged in successfully',
            'role': user['role'],
        }))
        resp.set_cookie('auth_token', token,
                        httponly=True, secure=False,
                        samesite='Lax', max_age=8*3600)
        return resp, 200   # ← must return resp here

    return jsonify({'message': 'Invalid credentials'}), 401

def logout_user():
    resp = make_response(jsonify({'message': 'Logged out successfully'}))
    resp.set_cookie('auth_token', '', expires=0)
    return resp
