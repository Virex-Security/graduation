"""
Standardized API response helpers.
All API endpoints should return responses through these helpers
to ensure consistent structure across the entire application.
"""
from flask import jsonify


# ── Success ────────────────────────────────────────────────────────────────

def ok(data=None, message: str = "OK", status: int = 200):
    """200 success with optional payload."""
    body = {"success": True, "message": message}
    if data is not None:
        body["data"] = data
    return jsonify(body), status


def created(data=None, message: str = "Created"):
    """201 created."""
    return ok(data=data, message=message, status=201)


# ── Client errors ──────────────────────────────────────────────────────────

def bad_request(message: str = "Bad request", errors=None):
    """400 bad request."""
    body = {"success": False, "message": message}
    if errors:
        body["errors"] = errors
    return jsonify(body), 400


def unauthorized(message: str = "Unauthorized"):
    """401 unauthorized."""
    return jsonify({"success": False, "message": message}), 401


def forbidden(message: str = "Forbidden"):
    """403 forbidden."""
    return jsonify({"success": False, "message": message}), 403


def not_found(message: str = "Not found"):
    """404 not found."""
    return jsonify({"success": False, "message": message}), 404


def conflict(message: str = "Conflict"):
    """409 conflict (e.g. duplicate username)."""
    return jsonify({"success": False, "message": message}), 409


def rate_limited(message: str = "Too many requests"):
    """429 rate limited."""
    return jsonify({"success": False, "message": message}), 429


# ── Server errors ──────────────────────────────────────────────────────────

def server_error(message: str = "Internal server error"):
    """500 internal server error. Never expose exception details."""
    return jsonify({"success": False, "message": message}), 500


# ── List wrapper ───────────────────────────────────────────────────────────

def paginated(items: list, total: int = None, message: str = "OK"):
    """Consistent list response with item count."""
    return jsonify({
        "success": True,
        "message": message,
        "data": items,
        "total": total if total is not None else len(items),
    }), 200
