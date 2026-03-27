"""
simple_app.py — Thin wrapper (لا يحتوي على logic مكررة)
يستورد مباشرة من app/api/routes.py
"""
from app.api.routes import create_api_app

app = create_api_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
