from functools import wraps
from flask import request, jsonify, redirect, url_for, current_app
import jwt
from roles import Role
from models import user_manager

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('auth_token')
        if not token:
            if request.path.startswith('/api/'):
                return jsonify({'message': 'Token is missing!'}), 401
            return redirect(url_for('login_page'))
            
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            user = user_manager.get_user(data['user'])
            if not user:
                if request.path.startswith('/api/'):
                    return jsonify({'message': 'User not found!'}), 401
                return redirect(url_for('login_page'))
            
            # Add username to user object for convenience
            current_user = user.copy()
        except Exception as e:
            if request.path.startswith('/api/'):
                return jsonify({'message': 'Token is invalid!'}), 401
            return redirect(url_for('login_page'))
            
        return f(current_user, *args, **kwargs)
    return decorated

def require_role(role):
    def decorator(f):
        @wraps(f)
        @token_required
        def decorated(current_user, *args, **kwargs):
            if current_user['role'] != role and current_user['role'] != Role.ADMIN:
                if request.path.startswith('/api/'):
                    return jsonify({'message': f'{role.capitalize()} access required!'}), 403
                return "Access Denied: Unprivileged access attempt.", 403
            return f(current_user, *args, **kwargs)
        return decorated
    return decorator

def admin_required(f):
    return require_role(Role.ADMIN)(f)
