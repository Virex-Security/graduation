"""
Incident Management - Incident tracking and response
"""
import time
import random


class Incident:
    """Represents a security incident with tracking and action history"""
    
    def __init__(self, category, source_ip, initial_event, detection_type="Other"):
        self.id = f"INC-{int(time.time())}-{random.randint(100, 999)}"
        self.category = category
        self.source_ip = source_ip
        self.detection_type = detection_type
        self.status = "Detected"
        self.severity = initial_event.get('severity', 'Medium')
        self.first_seen = initial_event['timestamp']
        self.last_seen = initial_event['timestamp']
        self.events = [initial_event]
        self.actions = []
