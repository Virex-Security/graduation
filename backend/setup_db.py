"""
Virex Security System — Database Setup Script
==============================================
Idempotent: safe to run multiple times.
Supports both SQLite (development) and PostgreSQL (production).

Usage:
    python setup_db.py
"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()

print("=" * 50)
print("  Virex DB Setup")
print("=" * 50)

db_url = os.getenv("DATABASE_URL", "")

if not db_url:
    print("\n  ERROR: DATABASE_URL not set in .env")
    print("  For local development set:")
    print("    DATABASE_URL=sqlite:///data/virex.db")
    print("  For production set a PostgreSQL URL.")
    sys.exit(1)

dialect = "SQLite" if db_url.startswith("sqlite") else "PostgreSQL"
print(f"\n  Backend : {dialect}")

# Show safe portion of URL (no passwords)
safe = db_url.split("@")[-1] if "@" in db_url else db_url
print(f"  URL     : {safe}\n")

from app.database import init_db

init_db()

print("\n" + "=" * 50)
print("  Setup complete! Now run:")
print("    python run_api.py")
print("    python run_dashboard.py")
print("=" * 50)
