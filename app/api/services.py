"""
API Services - Business logic backed by SQLite DB
==================================================
تم استبدال FAKE_USERS / FAKE_ORDERS / FAKE_PRODUCTS
بـ SQLite queries حقيقية من app/database.py
"""
import time
from collections import deque
from app import database as db

# In-memory request log (last 50 requests)
request_log = deque(maxlen=50)


def log_request(endpoint, method, ip, status, payload=""):
    """Log a request to the in-memory request log."""
    request_log.appendleft({
        'time':     time.strftime("%H:%M:%S"),
        'endpoint': endpoint,
        'method':   method,
        'ip':       ip,
        'status':   status,
        'payload':  str(payload)[:80] if payload else ""
    })


# ── Users ─────────────────────────────────────────────────────
def get_users(search_query=None) -> list:
    all_users = db.get_all_users()
    if search_query:
        q = search_query.lower()
        return [u for u in all_users
                if q in u.get('username', '').lower()
                or q in u.get('email', '').lower()]
    return all_users


# ── Orders ────────────────────────────────────────────────────
def get_orders(user_filter=None) -> list:
    return db.get_orders(user_filter=user_filter)


def create_order(user, product, price) -> dict:
    return db.create_order(user, product, price)


# ── Products ──────────────────────────────────────────────────
def get_products(category=None, search_query=None) -> list:
    return db.get_products(category=category, search=search_query)


# ── Request log ───────────────────────────────────────────────
def get_request_logs() -> list:
    return list(request_log)
