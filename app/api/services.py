"""
API Services - Business logic and data handlers
"""
import time
from collections import deque

# ── FAKE DATABASE ──────────────────────────────────────
FAKE_USERS = [
    {'id': 1,  'username': 'ahmed.hassan',   'email': 'ahmed@shop.com',   'role': 'admin',    'joined': '2024-01-10', 'orders': 14},
    {'id': 2,  'username': 'sara.ali',        'email': 'sara@shop.com',    'role': 'user',     'joined': '2024-02-15', 'orders': 8},
    {'id': 3,  'username': 'omar.khalid',     'email': 'omar@shop.com',    'role': 'user',     'joined': '2024-03-01', 'orders': 22},
    {'id': 4,  'username': 'lina.mostafa',    'email': 'lina@shop.com',    'role': 'user',     'joined': '2024-03-20', 'orders': 5},
    {'id': 5,  'username': 'karim.farouk',    'email': 'karim@shop.com',   'role': 'manager',  'joined': '2024-04-05', 'orders': 0},
    {'id': 6,  'username': 'nour.ibrahim',    'email': 'nour@shop.com',    'role': 'user',     'joined': '2024-05-12', 'orders': 17},
    {'id': 7,  'username': 'youssef.samir',   'email': 'youssef@shop.com', 'role': 'user',     'joined': '2024-06-08', 'orders': 3},
    {'id': 8,  'username': 'dina.ramadan',    'email': 'dina@shop.com',    'role': 'user',     'joined': '2024-07-19', 'orders': 11},
]

FAKE_ORDERS = [
    {'id': 1001, 'user': 'sara.ali',      'product': 'iPhone 15 Pro',       'price': 1299.99, 'status': 'delivered', 'date': '2025-01-05'},
    {'id': 1002, 'user': 'omar.khalid',   'product': 'Samsung Galaxy S24',  'price': 999.00,  'status': 'shipped',   'date': '2025-01-08'},
    {'id': 1003, 'user': 'ahmed.hassan',  'product': 'MacBook Air M3',      'price': 1499.00, 'status': 'delivered', 'date': '2025-01-12'},
    {'id': 1004, 'user': 'lina.mostafa',  'product': 'AirPods Pro',         'price': 249.99,  'status': 'pending',   'date': '2025-01-15'},
    {'id': 1005, 'user': 'nour.ibrahim',  'product': 'Sony WH-1000XM5',     'price': 349.00,  'status': 'delivered', 'date': '2025-01-18'},
    {'id': 1006, 'user': 'youssef.samir', 'product': 'iPad Pro 12.9',       'price': 1099.00, 'status': 'shipped',   'date': '2025-01-20'},
    {'id': 1007, 'user': 'dina.ramadan',  'product': 'Dell XPS 15',         'price': 1799.00, 'status': 'processing','date': '2025-01-22'},
    {'id': 1008, 'user': 'omar.khalid',   'product': 'Apple Watch Ultra 2', 'price': 799.00,  'status': 'delivered', 'date': '2025-01-25'},
    {'id': 1009, 'user': 'sara.ali',      'product': 'Logitech MX Master 3','price': 99.99,   'status': 'pending',   'date': '2025-01-28'},
    {'id': 1010, 'user': 'ahmed.hassan',  'product': 'LG OLED 4K 55"',      'price': 1599.00, 'status': 'shipped',   'date': '2025-02-01'},
]

FAKE_PRODUCTS = [
    {'id': 1, 'name': 'iPhone 15 Pro',        'category': 'phones',      'price': 1299.99, 'stock': 45},
    {'id': 2, 'name': 'Samsung Galaxy S24',   'category': 'phones',      'price': 999.00,  'stock': 30},
    {'id': 3, 'name': 'MacBook Air M3',        'category': 'laptops',     'price': 1499.00, 'stock': 20},
    {'id': 4, 'name': 'Sony WH-1000XM5',       'category': 'audio',       'price': 349.00,  'stock': 60},
    {'id': 5, 'name': 'iPad Pro 12.9',         'category': 'tablets',     'price': 1099.00, 'stock': 25},
    {'id': 6, 'name': 'Dell XPS 15',           'category': 'laptops',     'price': 1799.00, 'stock': 15},
    {'id': 7, 'name': 'AirPods Pro',           'category': 'audio',       'price': 249.99,  'stock': 80},
    {'id': 8, 'name': 'Apple Watch Ultra 2',   'category': 'wearables',   'price': 799.00,  'stock': 35},
    {'id': 9, 'name': 'LG OLED 4K 55"',        'category': 'displays',    'price': 1599.00, 'stock': 12},
    {'id': 10,'name': 'Logitech MX Master 3',  'category': 'accessories', 'price': 99.99,   'stock': 100},
]

# In-memory request log (last 50)
request_log = deque(maxlen=50)


def log_request(endpoint, method, ip, status, payload=""):
    """Log a request to the in-memory request log"""
    request_log.appendleft({
        'time':     time.strftime("%H:%M:%S"),
        'endpoint': endpoint,
        'method':   method,
        'ip':       ip,
        'status':   status,
        'payload':  str(payload)[:80] if payload else ""
    })


def get_users(search_query=None):
    """Get users, optionally filtered by search query"""
    if search_query:
        q = search_query.lower()
        results = [u for u in FAKE_USERS if q in u['username'].lower() or q in u['email'].lower()]
    else:
        results = FAKE_USERS
    return results


def get_orders(user_filter=None):
    """Get orders, optionally filtered by user"""
    if user_filter:
        results = [o for o in FAKE_ORDERS if user_filter in o['user']]
    else:
        results = FAKE_ORDERS
    return results


def get_products(category=None, search_query=None):
    """Get products, optionally filtered by category and/or search query"""
    results = FAKE_PRODUCTS
    
    if category and category != 'all':
        results = [p for p in results if p['category'] == category.lower()]
    
    if search_query:
        q = search_query.lower()
        results = [p for p in results if q in p['name'].lower()]
    
    return results


def create_order(user, product, price):
    """Create a new order"""
    new_order = {
        'id':      1000 + len(FAKE_ORDERS) + 1,
        'user':    user or 'guest',
        'product': product or 'Unknown',
        'price':   price or 0,
        'status':  'pending',
        'date':    time.strftime("%Y-%m-%d")
    }
    FAKE_ORDERS.append(new_order)
    return new_order


def get_request_logs():
    """Get the request log"""
    return list(request_log)
