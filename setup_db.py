"""
Virex Security System — Supabase Setup Script
==============================================
Run this once before starting the app for the first time.
Seeds initial data (roles, default admin, WAF rules) into Supabase.

Tables must be created in Supabase dashboard first.
See: https://supabase.com/dashboard/project/_/editor

Usage:
    python setup_db.py
"""
import os
from dotenv import load_dotenv

load_dotenv()

print("=" * 50)
print("  Virex DB Setup — Supabase")
print("=" * 50)
print(f"\n  Supabase URL: {os.getenv('SUPABASE_URL', 'NOT SET')}\n")

if not os.getenv("SUPABASE_URL") or not os.getenv("SUPABASE_KEY"):
    print("  ERROR: SUPABASE_URL and SUPABASE_KEY must be set in .env")
    print("  Copy .env.example to .env and fill in your Supabase credentials.")
    exit(1)

from app.database import init_db

init_db()

print("\n" + "=" * 50)
print("  Setup complete! Now run:")
print("    python run_api.py")
print("    python run_dashboard.py")
print("=" * 50)
