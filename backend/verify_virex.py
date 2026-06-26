import ast, os, sys, re

ROOT = os.getcwd()
results = []

def check(name, passed, detail=""):
    results.append((name, passed, detail))

files = [
    "app/ml/inference.py",
    "app/api/security.py",
    "app/api/routes.py",
    "app/auth/decorators.py",
    "app/auth/models.py",
    "simple_app.py",
]
for f in files:
    path = os.path.join(ROOT, f)
    if not os.path.exists(path):
        check(f"Syntax: {f}", False, "FILE MISSING"); continue
    try:
        ast.parse(open(path, encoding="utf-8").read())
        check(f"Syntax OK: {f}", True)
    except SyntaxError as e:
        check(f"Syntax: {f}", False, str(e))

routes = open(os.path.join(ROOT, "app/api/routes.py"), encoding="utf-8").read()
cors_wildcard = bool(re.search(r'origins.*[=:]\s*["\']?\*["\']?', routes))
check('CORS: no wildcard in origins', not cors_wildcard, 'still has wildcard')
check('CORS: ALLOWED_ORIGINS used',   'ALLOWED_ORIGINS' in routes, 'missing')
check('IP: _get_real_ip()',           '_get_real_ip' in routes, 'missing')
check('IP: X-Forwarded-For',         'X-Forwarded-For' in routes, 'missing')
check('Scan: request.form',          'request.form' in routes, 'missing')
check('Scan: request.files',         'request.files' in routes, 'missing')
check('Config: MAX_CONTENT_LENGTH',  'MAX_CONTENT_LENGTH' in routes, 'missing')
check('Scanner: startswith',         'startswith' in routes, 'still uses "in"')

dec = open(os.path.join(ROOT, "app/auth/decorators.py"), encoding="utf-8").read()
check('JWT: ExpiredSignatureError',  'ExpiredSignatureError' in dec, 'missing')

models = open(os.path.join(ROOT, "app/auth/models.py"), encoding="utf-8").read()
check('UserManager: threading.Lock', 'threading.Lock' in models, 'no lock')
check('UserManager: atomic write',   'tempfile' in models, 'no atomic write')

ml = open(os.path.join(ROOT, "app/ml/inference.py"), encoding="utf-8").read()
check('ML: predict_proba',           'predict_proba' in ml, 'missing')
check('ML: LRU Cache',               '_LRUCache' in ml, 'missing')
check('ML: Feedback Loop',           'ml_feedback.json' in ml, 'missing')
check('ML: ThreadPoolExecutor',      'ThreadPoolExecutor' in ml, 'missing')
check('ML: THRESHOLD_BLOCK',         'THRESHOLD_BLOCK' in ml, 'missing')
check('ML: MLDecision class',        'MLDecision' in ml, 'missing')

sec = open(os.path.join(ROOT, "app/api/security.py"), encoding="utf-8").read()
check('Patterns: Command Injection', 'cmd_patterns' in sec, 'missing')
check('Patterns: Path Traversal',    'path_patterns' in sec, 'missing')

temp = os.path.join(ROOT, "app/dashboard/routes_temp.py")
check('Cleanup: routes_temp.py gone', not os.path.exists(temp), 'still exists!')

simple = open(os.path.join(ROOT, "simple_app.py"), encoding="utf-8").read()
check('simple_app: thin wrapper',    len(simple) < 300, f'still big ({len(simple)} bytes)')

env_path = os.path.join(ROOT, ".env")
check('.env file exists',            os.path.exists(env_path), 'run: copy .env.example .env')
if os.path.exists(env_path):
    env = open(env_path).read()
    check('SECRET_KEY changed',      'change-me-in-production' not in env, 'still default value!')

passed = sum(1 for _, p, _ in results if p)
total  = len(results)
print(f"\n{'='*55}")
print(f"  VIREX2 — {passed}/{total} checks passed")
print(f"{'='*55}")
for name, ok, detail in results:
    icon = "OK  " if ok else "FAIL"
    msg  = f"  [{icon}]  {name}"
    if not ok: msg += f"  <-- {detail}"
    print(msg)
print(f"{'='*55}\n")
if passed == total:
    print("  All checks passed!")
else:
    print(f"  Fix the {total-passed} FAIL items above.")
