from functools import wraps
from flask import request, jsonify, redirect, url_for, current_app
import jwt
from app.auth.roles import Role
from app.auth.models import user_manager


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
            user = user_manager.get_user(data['username'])
            if not user:
                if request.path.startswith('/api/'):
                    return jsonify({'message': 'User not found!'}), 401
                return redirect(url_for('login_page'))
            current_user = user.copy()
            # Ensure 'role' and 'username' are always set for downstream checks
            current_user["role"] = user.get("role_name") or "user"
            current_user["username"] = user.get("username")

        except jwt.ExpiredSignatureError:
            # ✅ FIX: فحص صريح للـ token المنتهي
            if request.path.startswith('/api/'):
                return jsonify({'message': 'Token has expired!'}), 401
            return redirect(url_for('login_page'))

        except jwt.InvalidTokenError:
            if request.path.startswith('/api/'):
                return jsonify({'message': 'Token is invalid!'}), 401
            return redirect(url_for('login_page'))

        except Exception:
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
            if current_user.get('role', 'viewer') != role and current_user.get('role', 'viewer') != Role.ADMIN:
                if request.path.startswith('/api/'):
                    return jsonify({'message': f'{role.capitalize()} access required!'}), 403
                return "Access Denied: Unprivileged access attempt.", 403
            return f(current_user, *args, **kwargs)
        return decorated
    return decorator

def admin_required(f):
    return require_role(Role.ADMIN)(f)
