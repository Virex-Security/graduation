"""
Dashboard Metrics - Helper functions for metric calculations
"""
from datetime import datetime
import time


# Connection States
CONNECTED = "Connected"
API_ISSUE = "With API Issue"
DISCONNECTED = "Disconnected"
WAITING = "Waiting for API"


def calculate_threat_score(threat):
    """
    Calculate a numeric threat score based on severity and type.
    Used for incident prioritization.
    """
    severity_scores = {
        'Critical': 100,
        'High': 75,
        'Medium': 50,
        'Low': 25,
        'Info': 10,
        'Clean': 0
    }
    
    type_multipliers = {
        'SQL Injection': 1.5,
        'XSS': 1.3,
        'Brute Force': 1.4,
        'Scanner': 1.1,
        'Rate Limit': 1.0,
        'ML Detection': 1.2
    }
    
    base_score = severity_scores.get(threat.get('severity', 'Medium'), 50)
    multiplier = type_multipliers.get(threat.get('type', ''), 1.0)
    
    return base_score * multiplier


def is_recent(timestamp_str, minutes=5):
    """
    Check if a timestamp is within the last N minutes.
    Used for highlighting recent threats.
    """
    try:
        threat_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        diff = (now - threat_time).total_seconds() / 60
        return diff <= minutes
    except:
        return False


def determine_threat_status(threat):
    """
    Determine the current status of a threat based on its properties.
    Returns: 'Active', 'Blocked', 'Investigating', or 'Resolved'
    """
    if threat.get('blocked'):
        return 'Blocked'
    
    # Check if it's a recent threat
    if is_recent(threat.get('timestamp', ''), minutes=10):
        return 'Active'
    
    # Check severity for investigation status
    if threat.get('severity') in ['Critical', 'High']:
        return 'Investigating'
    
    return 'Resolved'


def run_timeline_updates():
    """
    Background thread function for updating timeline data.
    This is imported and used by the dashboard app.
    """
    while True:
        time.sleep(10)  # Update every 10 seconds
        # The actual update logic is handled by SecurityDashboard.update_timeline()
