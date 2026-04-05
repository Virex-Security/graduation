"""
patch_1_otp_hash.py
====================
يعدّل ملف app/dashboard/routes.py لتخزين OTP كـ hash بدل plain text
شغّله من جذر المشروع (نفس مكان requirements.txt):
    python patches/patch_1_otp_hash.py
"""

import re
from pathlib import Path

TARGET = Path("app/dashboard/routes.py")

if not TARGET.exists():
    print(f"[ERROR] مش لاقي الملف: {TARGET}")
    print("        تأكد إنك شغّل السكريبت من جذر المشروع")
    raise SystemExit(1)

src = TARGET.read_text(encoding="utf-8")
original = src  # نحتفظ بنسخة احتياطية


# ── 1. أضف import hashlib لو مش موجود ──────────────────────────────────────
if "import hashlib" not in src:
    src = src.replace("import hmac\n", "import hmac\nimport hashlib\n", 1)
    if "import hashlib" not in src:
        # fallback: حطّه بعد import secrets
        src = src.replace("import secrets\n", "import secrets\nimport hashlib\n", 1)

# أضف _otp_attempts tracker بعد السطر اللي فيه SMTP_PASSWORD
OTP_TRACKER = """\
    # ── OTP Rate-Limit Tracker (Fix 2) ──────────────────────────────────────
    from collections import defaultdict as _defaultdict
    _otp_attempts: dict = _defaultdict(list)
    _OTP_MAX   = 5
    _OTP_WIN   = 300  # ثانية
"""

marker = "    SMTP_EMAIL    = os.getenv('SMTP_EMAIL')"
if marker in src and "_otp_attempts" not in src:
    src = src.replace(marker, OTP_TRACKER + "\n" + marker)


# ── 2. Fix request_reset_otp: خزّن hash بدل plain text ─────────────────────
OLD_INSERT = (
    "        otp = str(secrets.randbelow(900000) + 100000) \n"
    "        expiry = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 300))\n"
    "        with _db.db_cursor() as cur:\n"
    "            cur.execute('DELETE FROM password_resets WHERE user_id = ?', (user_id,))\n"
    "            cur.execute('INSERT INTO password_resets (user_id, otp, otp_expiry, used) VALUES (?,?,?,0)',\n"
    "                        (user_id, otp, expiry))"
)

NEW_INSERT = (
    "        otp = str(secrets.randbelow(900000) + 100000)\n"
    "        otp_hash = hashlib.sha256(otp.encode()).hexdigest()  # FIX-1: نخزن hash\n"
    "        expiry = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 300))\n"
    "        with _db.db_cursor() as cur:\n"
    "            cur.execute('DELETE FROM password_resets WHERE user_id = ?', (user_id,))\n"
    "            cur.execute('INSERT INTO password_resets (user_id, otp, otp_expiry, used) VALUES (?,?,?,0)',\n"
    "                        (user_id, otp_hash, expiry))  # FIX-1: otp_hash مش otp"
)

if OLD_INSERT in src:
    src = src.replace(OLD_INSERT, NEW_INSERT)
    print("[FIX-1] تخزين OTP كـ hash ✅")
else:
    print("[WARN]  مش لاقي مكان INSERT القديم — ممكن يكون اتعدّل قبل كده")


# ── 3. Fix verify_reset_otp: قارن hash بـ hash + أضف rate limiting ──────────
OLD_VERIFY_START = (
    "    @app.route('/api/verify-reset-otp', methods=['POST'])\n"
    "    def verify_reset_otp():\n"
    "        data     = request.get_json(silent=True) or {}\n"
    "        user_id  = data.get('user_id')\n"
    "        otp      = data.get('otp', '').strip()\n"
    "        new_pass = data.get('new_password', '').strip()\n"
    "        if not user_id or not otp or not new_pass:\n"
    "            return jsonify({'error': 'user_id, otp and new_password required'}), 400\n"
    "        with _db.db_cursor() as cur:\n"
    "            cur.execute('SELECT * FROM password_resets WHERE user_id = ? AND used = 0', (user_id,))\n"
    "            record = cur.fetchone()\n"
    "        if not record:\n"
    "            return jsonify({'error': 'No OTP requested for this user'}), 400\n"
    "        if not hmac.compare_digest(record['otp'], str(otp)):\n"
    "            return jsonify({'error': 'Invalid OTP'}), 400"
)

NEW_VERIFY_START = (
    "    @app.route('/api/verify-reset-otp', methods=['POST'])\n"
    "    def verify_reset_otp():\n"
    "        import time as _time\n"
    "        data     = request.get_json(silent=True) or {}\n"
    "        user_id  = data.get('user_id')\n"
    "        otp      = data.get('otp', '').strip()\n"
    "        new_pass = data.get('new_password', '').strip()\n"
    "        if not user_id or not otp or not new_pass:\n"
    "            return jsonify({'error': 'user_id, otp and new_password required'}), 400\n"
    "        # FIX-2: rate limiting\n"
    "        _now = _time.time()\n"
    "        _key = str(user_id)\n"
    "        _otp_attempts[_key] = [t for t in _otp_attempts[_key] if _now - t < _OTP_WIN]\n"
    "        if len(_otp_attempts[_key]) >= _OTP_MAX:\n"
    "            return jsonify({'error': 'Too many attempts. Try again in 5 minutes.'}), 429\n"
    "        _otp_attempts[_key].append(_now)\n"
    "        with _db.db_cursor() as cur:\n"
    "            cur.execute('SELECT * FROM password_resets WHERE user_id = ? AND used = 0', (user_id,))\n"
    "            record = cur.fetchone()\n"
    "        if not record:\n"
    "            return jsonify({'error': 'No OTP requested for this user'}), 400\n"
    "        # FIX-1: قارن hash بـ hash\n"
    "        otp_hash = hashlib.sha256(otp.encode()).hexdigest()\n"
    "        if not hmac.compare_digest(record['otp'], otp_hash):\n"
    "            return jsonify({'error': 'Invalid OTP'}), 400"
)

if OLD_VERIFY_START in src:
    src = src.replace(OLD_VERIFY_START, NEW_VERIFY_START)
    print("[FIX-1+2] التحقق من hash + rate limiting ✅")
else:
    print("[WARN]    مش لاقي verify_reset_otp القديمة — ممكن تكون اتعدّلت")


# ── حفظ الملف ──────────────────────────────────────────────────────────────
if src != original:
    TARGET.write_text(src, encoding="utf-8")
    print(f"\n[DONE] تم تعديل {TARGET} بنجاح 🎉")
else:
    print("\n[INFO] مفيش تغييرات — الملف ربما اتعدّل قبل كده")
