from datetime import datetime, timedelta
import jwt
from flask import current_app, make_response, jsonify
from app.auth.models import user_manager
from app.auth.roles import Role

def login_user(username, password):
    user = user_manager.verify_password(username, password)
    if user:
        token = jwt.encode({
            'username': username,
            'user_id': user.get('user_id'),
            'role': user.get('role_name', 'user'),
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, current_app.config['SECRET_KEY'], algorithm="HS256")
        
        resp = make_response(jsonify({
            'message': 'Logged in successfully',
            'role': user.get('role', 'viewer'),
            'username': username
        }))
        resp.set_cookie('auth_token', token, httponly=True)
        return resp, 200
    
    return jsonify({'message': 'Invalid credentials'}), 401

def logout_user():
    resp = make_response(jsonify({'message': 'Logged out successfully'}))
    resp.set_cookie('auth_token', '', expires=0)
    return resp
