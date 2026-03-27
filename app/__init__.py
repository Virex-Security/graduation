"""
Virex Security System - Application Package
"""
__version__ = "1.0.0"

# Initialize DB once when the package is first imported
from app import database
database.init_db()
