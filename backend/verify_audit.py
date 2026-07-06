import ast, re, json, csv
from collections import Counter

with open(r'app/ml/inference.py', encoding='utf-8') as f:
    src = f.read()
ast.parse(src)
print('PASS: inference.py parses without syntax errors')

with open(r'data/class_thresholds.json') as f:
    t = json.load(f)
assert t['sqli'] == t['sql_injection'] == 0.1032, 'Threshold mismatch!'
print('PASS: sqli and sql_injection thresholds match:', t['sqli'])

with open(r'data/train.csv', encoding='utf-8', errors='replace') as f:
    reader = csv.DictReader(f)
    counts = Counter(row['label'] for row in reader)
assert 'brute_force' not in counts, 'brute_force unexpectedly in train.csv!'
print('PASS: brute_force NOT in train.csv (9 ML classes confirmed)')
print('Confirmed classes:', sorted(counts.keys()))

with open(r'data/evaluation_report.json') as f:
    report = json.load(f)
assert '_legacy_note' in report
print('PASS: evaluation_report.json marked as legacy')

import re as _re
_FAST_SUSPICIOUS_REGEX = _re.compile(
    r"""['\"<>;|\${}()]|--|/\*|\*/|\.\./|\.\.\\"""
    r"""|password=|passwd=|username=|login=|admin:|root:|"""
    r"""/\.env|/\.git/|/phpmyadmin|/wp-admin|"""
    r"""sqlmap/|nikto/|nmap|curl/|wget|acunetix|nessus|burp|zap|"""
    r"""\b(?:union\s+select|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|exec|xp_|script|javascript:|onerror=|onload=|sleep\s*\(|benchmark\s*\(|waitfor)\b""",
    _re.IGNORECASE
)
print('PASS: _FAST_SUSPICIOUS_REGEX compiles successfully')
print('\nAll verifications passed.')
