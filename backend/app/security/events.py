import time
import uuid

def new_request_id():
    return str(uuid.uuid4())

def now_ts():
    # string timestamp (easy for JSON/logs)
    return time.strftime("%Y-%m-%d %H:%M:%S")

def build_event(
    *,
    request_id,
    ip,
    endpoint,
    method,
    attack_type,
    severity="Medium",
    detection_type="Other",
    blocked=False,
    reason="",
    snippet=""
):
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": now_ts(),
        "request_id": request_id,
        "ip": ip,
        "endpoint": endpoint,
        "method": method,
        "attack_type": attack_type,
        "severity": severity,
        "detection_type": detection_type,
        "blocked": bool(blocked),
        "reason": reason,
        "snippet": snippet[:200] if snippet else ""
    }
