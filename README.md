VIREX Security System
Overview

VIREX is a real-time Web Application Firewall (WAF) and SIEM platform.
It inspects API requests, detects attacks using regex rules and ML, and provides a live threat monitoring dashboard.

Key Goals:

Protect APIs from SQL Injection, XSS, CSRF, SSRF, brute force, command injection, path traversal.
Provide real-time insights and alerts.
Automate attack detection and logging.
Features
Real-time WAF inspection
ML-based threat classification (Random Forest)
Live SIEM dashboard with charts and incident management
Role-based access with JWT authentication
Detailed attack logging
OTP-based password reset
Security chatbot assistant
Technology
Backend: Python 3.11, Flask, Gunicorn
Frontend: Jinja2, JavaScript, Chart.js, CSS
Database: SQLite
ML: scikit-learn, TF-IDF, pandas
Security: PyJWT, bcrypt, hashlib, hmac, secrets
Deployment: Docker & Docker Compose
Quick Start
Local
git clone <repo-url>
cd graduation
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python setup_db.py
python run_api.py
python run_dashboard.py

Access dashboard at http://localhost:8070/dashboard

Docker
docker-compose up --build
API: port 5000
Dashboard: port 8070
Contributing
Use feature branches
Test locally before PR
Open pull request for review
License

VIREX Team
