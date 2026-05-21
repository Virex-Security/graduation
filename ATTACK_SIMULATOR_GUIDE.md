# Attack Simulator Guide

## 🎯 Overview

The new `attack_simulator.py` targets **REAL vulnerabilities** in the Virex Security Dashboard project, not fake endpoints!

## ✅ What Changed

### Before (Old Simulator):
- ❌ Attacked fake endpoints that don't exist
- ❌ Generic CVE payloads not relevant to project
- ❌ No real testing of project security

### After (New Simulator):
- ✅ Attacks **REAL endpoints** in the project
- ✅ Tests **ACTUAL vulnerabilities**
- ✅ Generates realistic dataset for ML training
- ✅ Shows block rate and statistics

## 🚀 Usage

### 1. Start the Services

```bash
# Terminal 1: Start API
python run_api.py

# Terminal 2: Start Dashboard
python run_dashboard.py
```

### 2. Run the Simulator

```bash
python attack_simulator.py
```

**With custom URLs:**
```bash
python attack_simulator.py --dashboard http://localhost:8070 --api http://localhost:5000
```

## 🎯 What It Tests

### 1. SQL Injection (15 attacks)
**Targets:**
- `GET /api/users?search=`
- `GET /api/orders?user=`
- `GET /api/products?search=`
- `POST /api/login` (username field)

**Payloads:**
```sql
' OR '1'='1
admin'--
' UNION SELECT username,password FROM users--
'; DROP TABLE users--
```

### 2. XSS (12 attacks)
**Targets:**
- `POST /api/data` (comment, message, name fields)
- `POST /api/chatbot/message`
- `POST /api/user-manager/users` (full_name)

**Payloads:**
```html
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### 3. CSRF (10 attacks)
**Targets:**
- `POST /api/user-manager/users` (no CSRF token)
- `PUT /api/settings/profile`
- `DELETE /api/blacklist/1`

**Test:** Sends requests without CSRF token or Referer header

### 4. Path Traversal (10 attacks)
**Targets:**
- `GET /api/data?file=`
- `GET /static/uploads/avatars/`
- Direct path access

**Payloads:**
```
../../../etc/passwd
..\\..\\..\\windows\\system32
%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### 5. Brute Force (25 attempts)
**Target:**
- `POST /api/auth/login`

**Test:** Multiple login attempts with common credentials

### 6. Scanner Detection (15 probes)
**Targets:**
```
/.env
/.git/config
/admin
/db/virex.db
/data/users.json
```

**Test:** Probes sensitive paths with scanner User-Agent

### 7. Legitimate Traffic
**Purpose:** Mixed with attacks to test false positive rate

## 📊 Output

### Console Output:
```
🎯 Starting Attack Simulation...

  [SQLi] Testing 15 SQL injection attacks...
    [1/15] GET /api/users?search=' OR '1'='1... → 403 🛡️ BLOCKED
    [2/15] GET /api/orders?user=admin'--... → 200
    ...

  [Legit] Generating 10 normal requests...
    [1/10] GET http://localhost:5000/api/health → 200
    ...

✅ Dataset exported → data/real_attack_dataset.csv  (150 rows)

=================================================================
  Attack Statistics
=================================================================
  Total Attacks:  97
  Blocked:        45
  Block Rate:     46.4%
  Dataset Rows:   150
=================================================================
```

### Dataset CSV:
```csv
timestamp,attack_type,payload_snippet,label,status_code,blocked
2024-01-15T10:30:45,sqli,' OR '1'='1,1,403,True
2024-01-15T10:30:46,benign,normal_request,0,200,False
2024-01-15T10:30:47,xss,<script>alert(1)</script>,1,403,True
```

## 🔧 Customization

### Change Attack Counts:
```python
# In attack_simulator.py, modify:
self.sql_injection_attacks(15)  # Change to 30
self.xss_attacks(12)            # Change to 20
```

### Add New Attack Types:
```python
def custom_attack(self, num_attacks=10):
    """Your custom attack"""
    for i in range(num_attacks):
        payload = "your_payload"
        r = self._request("POST", f"{self.api_url}/your/endpoint", 
                         context, json_data={"field": payload})
        # Log results
        self._log_dataset("custom", payload, 1, r.status_code if r else None)
```

### Change Target URLs:
```bash
python attack_simulator.py --dashboard http://192.168.1.100:8070 --api http://192.168.1.100:5000
```

## 📈 Using the Dataset for ML

The generated dataset can be used to train the ML model:

```bash
# 1. Run simulator to generate dataset
python attack_simulator.py

# 2. Use the dataset for training
# Edit train_model.py to load data/real_attack_dataset.csv

# 3. Train model
python train_model.py
```

## ⚠️ Important Notes

1. **Run on localhost only** - Don't attack production systems
2. **Rate limiting** - The simulator respects rate limits (pauses between requests)
3. **Legitimate traffic** - Mixed with attacks to test false positives
4. **Block detection** - Tracks 403/429 responses as blocks

## 🎓 Understanding Results

### Good Security:
- Block Rate: >70%
- SQL Injection: >90% blocked
- XSS: >80% blocked
- Brute Force: >95% blocked after 5 attempts

### Needs Improvement:
- Block Rate: <50%
- CSRF: <30% blocked (missing token validation)
- Path Traversal: <60% blocked

### False Positives:
- Legitimate traffic blocked: Should be <5%
- Check logs for incorrectly blocked requests

## 🔍 Debugging

### If attacks aren't blocked:
1. Check WAF rules are loaded: `python setup_db.py`
2. Verify ML model is running: Check logs for `[ML] Model loaded`
3. Check rate limiting is enabled

### If too many false positives:
1. Lower ML threshold in `app/ml/inference_simple.py`
2. Review WAF rules for overly aggressive patterns
3. Check legitimate traffic patterns

---

**Questions?** Check `SECURITY.md` or open an issue.
