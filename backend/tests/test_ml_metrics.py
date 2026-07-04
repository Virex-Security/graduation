import pytest

def get_ml_relevant_logs(logs):
    filtered = []
    for l in logs:
        if 'action' in l:
            continue
        if str(l.get('detection_type', '')).lower() == 'rule':
            continue
        
        endpoint = l.get('endpoint', '')
        if endpoint and any(endpoint.startswith(p) for p in [
            '/dashboard', '/api/dashboard', '/login', '/signup',
            '/static/', '/blocked', '/incidents', '/requests',
            '/profile', '/ml-detections', '/threats/', '/critical'
        ]):
            continue
        if 'attack_type' in l or 'type' in l:
            filtered.append(l)
    return filtered


def compute_ml_metrics(logs, total_requests, normal_requests_count):
    # Isolated version of SecurityDashboard.compute_ml_metrics
    real_logs = get_ml_relevant_logs(logs)
    
    total_live = total_requests
    
    tp = fp = fn = 0
    for l in real_logs:
        is_attack = l.get('attack_type', 'Clean') not in ('Clean', 'False Positive', '', None)
        ml_flagged = l.get('ml_detected') is True or str(l.get('detection_type')).lower() == 'ml' or str(l.get('type')).lower() == 'ml detection'
        
        if ml_flagged and is_attack:
            tp += 1
        elif ml_flagged and not is_attack:
            fp += 1
        elif not ml_flagged and is_attack:
            fn += 1

    total_clean = normal_requests_count
    tn = max(0, total_clean - fp)

    total_evals = total_live
    if total_evals == 0:
        return {
            "live_data_active": False,
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "confusion_matrix": {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        }

    ml_events = tp + fp + fn
    if ml_events == 0:
        return {
            "live_data_active": False,
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "confusion_matrix": {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
        }

    accuracy = ((tp + tn) / total_evals) * 100 if total_evals > 0 else 0.0
    precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0.0
    
    if precision + recall > 0:
        f1_score = 2 * (precision * recall) / (precision + recall)
    else:
        f1_score = 0.0

    return {
        "live_data_active": True,
        "accuracy": round(accuracy, 2),
        "precision": round(precision, 2),
        "recall": round(recall, 2),
        "f1_score": round(f1_score, 2),
        "confusion_matrix": {
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn
        }
    }


def test_compute_ml_metrics_empty():
    metrics = compute_ml_metrics([], 0, 0)
    assert metrics['live_data_active'] is False
    assert metrics['accuracy'] == 0.0
    assert metrics['f1_score'] == 0.0
    assert metrics['confusion_matrix']['tp'] == 0

def test_compute_ml_metrics_regex_only():
    logs = [
        {'attack_type': 'SQL Injection', 'detection_type': 'rule', 'ml_detected': False, 'confidence': 0.0}
    ]
    metrics = compute_ml_metrics(logs, 1, 0)
    # ML shouldn't be penalized for Regex
    assert metrics['confusion_matrix']['fn'] == 0
    assert metrics['confusion_matrix']['tp'] == 0

def test_compute_ml_metrics_ml_detections():
    logs = [
        {'attack_type': 'SQL Injection', 'detection_type': 'ml', 'ml_detected': True, 'confidence': 0.99},
        {'attack_type': 'Clean', 'detection_type': 'ml', 'ml_detected': True, 'confidence': 0.85}, # FP
    ]
    metrics = compute_ml_metrics(logs, 100, 98)
    cm = metrics['confusion_matrix']
    assert cm['tp'] == 1
    assert cm['fp'] == 1
    assert cm['fn'] == 0
    # tn = total_clean - fp = 98 - 1 = 97
    assert cm['tn'] == 97
    assert metrics['accuracy'] > 0
    assert metrics['precision'] == 50.0

def test_compute_ml_metrics_mixed():
    logs = [
        {'attack_type': 'SQL Injection', 'detection_type': 'ml', 'ml_detected': True, 'confidence': 0.99},
        {'attack_type': 'XSS', 'detection_type': 'rule', 'ml_detected': False, 'confidence': 0.0},
        {'attack_type': 'Brute Force', 'detection_type': 'monitor', 'ml_detected': False, 'confidence': 0.10}, 
    ]
    metrics = compute_ml_metrics(logs, 50, 47)
    cm = metrics['confusion_matrix']
    assert cm['tp'] == 1
    assert cm['fp'] == 0
    assert cm['fn'] == 1 # The monitor event
