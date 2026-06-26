"""
analyze_waf_error.py - Diagnostic script for Virex Reverse Proxy WAF
"""

import sys
import threading
import json

# Ensure we can import the app
try:
    from app.api import create_api_app
    from app.api import routes
except ImportError as e:
    print(f"Import Error: {e}")
    print("Make sure you are running this from the project root (where run_api.py is).")
    sys.exit(1)

def run_diagnostics():
    print("="*60)
    print("  Virex WAF Architecture Diagnostic Tool")
    print("="*60)
    
    app = create_api_app()
    
    # ---------------------------------------------------------
    # 1. Hook Inspection
    # ---------------------------------------------------------
    print("\n[1] Hook Inspection: @app.before_request")
    hooks = app.before_request_funcs.get(None, [])
    before_req_names = [f.__name__ for f in hooks]
    print(f"    Registered global before_request hooks: {before_req_names}")
    
    if 'before_request' in before_req_names:
        print("    [PASS] WAF before_request hook is globally registered.")
        print("           It WILL intercept all traffic BEFORE local Flask routes or Proxy triggers.")
    else:
        print("    [FAIL] WAF before_request hook is MISSING!")

    # ---------------------------------------------------------
    # 2. Variable Scope Check & Thread Isolation
    # ---------------------------------------------------------
    print("\n[2] Variable Scope & Thread Safety Check")
    total_val = getattr(routes, '_total_requests_count', None)
    normal_val = getattr(routes, '_normal_requests_count', None)
    
    print(f"    _total_requests_count defined in routes.py: {total_val is not None}")
    print(f"    _normal_requests_count defined in routes.py: {normal_val is not None}")
    
    print("    [ANALYSIS] In Flask, global variables (`global _total_requests_count`) are shared")
    print("               across threads in the same worker process. Due to Python's GIL, simple")
    print("               `+= 1` increments are thread-safe. However, if deployed using Gunicorn")
    print("               with multiple *processes* (workers), global variables are ISOLATED per")
    print("               process and will DESYNC.")
    print("    [FIX]      The true source of truth is `security.total_requests` and the DB.")
    print("               `security._persist_stats()` writes these to the DB. Ensure it is called")
    print("               on every request path (both block and pass).")

    # ---------------------------------------------------------
    # 3. Route Extraction Logic (request.get_json)
    # ---------------------------------------------------------
    print("\n[3] Route Extraction Logic (Empty JSON body vulnerability)")
    
    # We inspect the code structure directly from the file text
    import os
    routes_path = os.path.join(os.path.dirname(__file__), 'app', 'api', 'routes.py')
    try:
        with open(routes_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        has_silent = 'request.get_json(silent=True)' in source_code
    except Exception as e:
        has_silent = False
        print(f"    [ERROR] Could not read routes.py: {e}")
    
    if has_silent:
        print("    [PASS] `request.get_json(silent=True)` is present in before_request.")
        print("           `silent=True` correctly prevents native Flask 400/415 crashes on empty bodies.")
    else:
        print("    [WARNING] `request.get_json(silent=True)` NOT found!")
        print("           If `silent=True` is missing, Flask aborts the request before the WAF can inspect it.")

    # ---------------------------------------------------------
    # 4. Endpoint Resolution
    # ---------------------------------------------------------
    print("\n[4] Endpoint Resolution Analysis (Local vs Proxy)")
    
    # Extract the local routes tuple from routes.py
    local_routes = getattr(routes, '_LOCAL_ROUTES', [])
    if not local_routes:
        # Fallback if the variable was named something else
        local_routes = getattr(routes, '_local_prefixes', [])
        
    print(f"    Registered local bypass prefixes: {local_routes}")
    
    test_paths = ['/products', '/api/users', '/health', '/api/dashboard/stats', '/', '/wp-admin']
    
    for path in test_paths:
        is_local = path == "/" or any(path.startswith(p) for p in local_routes)
        routing = '[LOCAL BYPASS]' if is_local else '[WAF + PROXY]'
        print(f"    Path: {path:<20} -> {routing}")
        
        if path == '/products' and is_local:
            print("    [WARNING] /products is being bypassed! It will not reach the reverse proxy!")

    print("\n" + "="*60)
    print("  Diagnostic Complete")
    print("="*60)

if __name__ == "__main__":
    run_diagnostics()
