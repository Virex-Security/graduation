def is_trivial(req):
    """
    Determine if a request is trivial (monitoring/health checks).
    Trivial requests are NEVER counted in any metric.
    """
    path = req.path

    # Health and status checks
    if path in ['/health', '/api/health', '/status', '/ping']:
        return True

    # Dashboard internal APIs
    if path.startswith('/api/dashboard/'):
        return True

    # Static files
    static_extensions = ['.js', '.css', '.png', '.jpg', '.ico', '.svg', '.woff', '.ttf']
    if any(path.endswith(ext) for ext in static_extensions):
        return True

    # Stats endpoint (monitoring only)
    if path == '/api/security/stats':
        return True

    return False


def is_business_relevant(req):
    """
    Determine if a request represents real business interaction.
    Only business-relevant requests count as total_requests (if not blocked).

    Business-relevant criteria:
    - POST/PUT/PATCH/DELETE to any endpoint
    - Access to sensitive endpoints (login, admin, data, user, transaction)
    - Any request to /api/* endpoints (except health/dashboard)
    """
    path = req.path
    method = req.method

    # All data-modifying methods are business-relevant
    if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
        return True

    # Any API endpoint (except health and dashboard)
    if path.startswith('/api/') and not path.startswith('/api/dashboard/') and path not in ['/api/health', '/api/security/stats']:
        return True

    # Sensitive endpoints (even GET)
    sensitive_endpoints = [
        '/login', '/api/login',
        '/admin', '/api/admin',
        '/api/data',
        '/user/', '/api/user/',
        '/transaction/', '/api/transaction/'
    ]
    if any(path.startswith(x) for x in sensitive_endpoints):
        return True

    return False