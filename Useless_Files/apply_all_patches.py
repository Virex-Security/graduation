"""
apply_all_patches.py
=====================
يطبق كل الـ patches بالترتيب الصح.

الاستخدام:
    python apply_all_patches.py

لازم تشغّله من جذر المشروع (نفس مكان requirements.txt)
"""

import sys
import subprocess
from pathlib import Path

# تأكد إننا في جذر المشروع
if not Path("requirements.txt").exists():
    print("[ERROR] شغّل السكريبت ده من جذر المشروع")
    print("        يعني نفس المجلد اللي فيه requirements.txt")
    sys.exit(1)

PATCHES_DIR = Path(__file__).parent / "patches"

patches = [
    ("patch_1_otp_hash.py",         "Fix 1+2 — OTP hash + rate limiting"),
    ("patch_2_security_headers.py", "Fix 3+4+6 — /health split + CSP + headers"),
    ("patch_3_requirements.py",     "Fix 5 — Dependencies upgrade"),
]

print("=" * 55)
print("  Virex Security — Applying All Fixes")
print("=" * 55)

all_ok = True
for filename, description in patches:
    patch_path = PATCHES_DIR / filename
    print(f"\n{'─'*55}")
    print(f"  {description}")
    print(f"{'─'*55}")

    if not patch_path.exists():
        print(f"[ERROR] مش لاقي الملف: {patch_path}")
        all_ok = False
        continue

    result = subprocess.run(
        [sys.executable, str(patch_path)],
        capture_output=False
    )

    if result.returncode != 0:
        print(f"[ERROR] فشل الـ patch: {filename}")
        all_ok = False

print("\n" + "=" * 55)
if all_ok:
    print("  كل الـ patches اتطبقت بنجاح ✅")
    print()
    print("  الخطوة الأخيرة — حدّث الـ packages:")
    print("  pip install -r requirements.txt --upgrade")
else:
    print("  في بعض الـ patches اللي محتاج تراجعها ⚠️")
print("=" * 55)
