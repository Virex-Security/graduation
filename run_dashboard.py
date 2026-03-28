"""
Dashboard Entry Point - Start the SIEM Dashboard server
"""
import os
from dotenv import load_dotenv
from app.dashboard import create_dashboard_app

load_dotenv()

if __name__ == '__main__':
    print("📊 SIEM Dashboard Started")
    app = create_dashboard_app()
    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
    app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
    app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
    dashboard_port = int(os.getenv("DASHBOARD_PORT", 8070))
    app.run(host="0.0.0.0", port=dashboard_port, debug=True)
