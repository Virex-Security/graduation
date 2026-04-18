"""
patch_3_requirements.py
========================
يعدّل requirements.txt:
  - Fix-5: يرفع Flask لـ 3.0.3
  - Fix-5: يثبت werkzeug بـ version محددة
  - Fix-5: يشيل flask-limiter (مش بتستخدمه)

شغّله من جذر المشروع:
    python patches/patch_3_requirements.py
"""

from pathlib import Path

TARGET = Path("requirements.txt")

if not TARGET.exists():
    print(f"[ERROR] مش لاقي الملف: {TARGET}")
    raise SystemExit(1)

src = TARGET.read_text(encoding="utf-8")
original = src

# Flask upgrade
if "flask==2.2.5" in src.lower():
    src = src.replace("flask==2.2.5", "flask==3.0.3")
    print("[FIX-5] Flask 2.2.5 → 3.0.3 ✅")

# شيل flask-limiter
lines = src.splitlines()
new_lines = []
for line in lines:
    stripped = line.strip().lower()
    if stripped.startswith("flask-limiter"):
        new_lines.append("# " + line + "  # FIX-5: removed — not used, reduces attack surface")
        print("[FIX-5] flask-limiter commented out ✅")
    else:
        new_lines.append(line)
src = "\n".join(new_lines)

# أضف werkzeug مثبت لو مش موجود
if "werkzeug==" not in src.lower():
    src = src.replace(
        "flask==3.0.3",
        "flask==3.0.3\nwerkzeug==3.0.3        # FIX-5: pinned version"
    )
    print("[FIX-5] werkzeug==3.0.3 pinned ✅")

if src != original:
    TARGET.write_text(src, encoding="utf-8")
    print(f"\n[DONE] تم تعديل {TARGET} بنجاح 🎉")
    print("\n[ACTION] شغّل الأمر ده عشان تطبق التحديثات:")
    print("         pip install -r requirements.txt --upgrade")
else:
    print("\n[INFO] مفيش تغييرات")
