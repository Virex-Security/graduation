"""
Standardized API response helpers.
All API endpoints should return responses through these helpers
to ensure consistent structure across the entire application.
"""
from flask import jsonify


# ── Success ────────────────────────────────────────────────────────────────

def ok(data=None, status: int = 200):
    """200 success with payload."""
    return jsonify({
        "success": True,
        "data": data,
        "error": None
    }), status


def created(data=None):
    """201 created."""
    return ok(data=data, status=201)


# ── Client errors ──────────────────────────────────────────

def error(message: str, data=None, status: int = 400):
    """Standard error response."""
    return jsonify({
        "success": False,
        "data": data,
        "error": message
    }), status


def bad_request(message: str = "Bad request", errors=None):
    """400 bad request."""
    return error(message, data=errors, status=400)


def unauthorized(message: str = "Unauthorized"):
    """401 unauthorized."""
    return error(message, status=401)


def forbidden(message: str = "Forbidden"):
    """403 forbidden."""
    return error(message, status=403)


def not_found(message: str = "Not found"):
    """404 not found."""
    return error(message, status=404)


def conflict(message: str = "Conflict"):
    """409 conflict."""
    return error(message, status=409)


def rate_limited(message: str = "Too many requests"):
    """429 rate limited."""
    return error(message, status=429)


# ── Server errors ──────────────────────────────────────────

def server_error(message: str = "Internal server error"):
    """500 internal server error."""
    return error(message, status=500)


# ── List wrapper ───────────────────────────────────────────

def paginated(items: list, total: int = None, message: str = "OK"):
    """Consistent list response with meta-data nested in data."""
    data = {
        "items": items,
        "total": total if total is not None else len(items),
        "message": message
    }
    return ok(data=data)
