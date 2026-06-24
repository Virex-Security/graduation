import os
import json
from app.database import clear_threat_logs
from app.dashboard.services import SecurityDashboard

def reset_all_logs():
    print("[*] Starting full reset of Virex Security logs...")

    # 1. Clear PostgreSQL database logs
    try:
        clear_threat_logs()
        print("[+] PostgreSQL threat logs, incidents, and stats cleared successfully.")
    except Exception as e:
        print(f"[-] Failed to clear DB: {e}")

    # 2. Clear JSON Audit Log
    dashboard = SecurityDashboard()
    audit_path = dashboard.audit_log_path
    try:
        with open(audit_path, 'w') as f:
            json.dump([], f)
        print(f"[+] Audit log JSON ({audit_path}) cleared successfully.")
    except Exception as e:
        print(f"[-] Failed to clear audit log: {e}")

    print("[*] Reset complete! Your dashboard is now completely fresh for the demo.")

if __name__ == "__main__":
    # Ensure the environment variables (like DB credentials) are loaded
    from dotenv import load_dotenv
    load_dotenv()
    
    reset_all_logs()
