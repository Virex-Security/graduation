"""
patch_2_security_headers.py
============================
يعدّل app/api/routes.py:
  - Fix-3: يقسم /health لـ public (status فقط) + /health/detailed للأدمن
  - Fix-4: يصلح Content-Security-Policy
  - Fix-6: يشيل X-XSS-Protection القديم ويضيف Permissions-Policy

شغّله من جذر المشروع:
    python patches/patch_2_security_headers.py
"""

from pathlib import Path

TARGET = Path("app/api/routes.py")

if not TARGET.exists():
    print(f"[ERROR] مش لاقي الملف: {TARGET}")
    raise SystemExit(1)

src = TARGET.read_text(encoding="utf-8")
original = src


# ── FIX-3: تقسيم /health ────────────────────────────────────────────────────
OLD_HEALTH = (
    "    @app.route(\"/health\")\n"
    "    def health():\n"
    "        return {\"status\": \"healthy\", \"uptime\": time.time() - security.start_time,\n"
    "                \"total_requests\": security.total_requests,\n"
    "                \"blocked_requests\": security.blocked_requests}"
)

NEW_HEALTH = (
    "    @app.route(\"/health\")\n"
    "    def health():\n"
    "        # FIX-3: public endpoint — status only, no sensitive metrics\n"
    "        return {\"status\": \"healthy\"}, 200\n"
    "\n"
    "    @app.route(\"/health/detailed\")\n"
    "    @token_required\n"
    "    @admin_required\n"
    "    def health_detailed(current_user):\n"
    "        # FIX-3: metrics متاحة للأدمن بس\n"
    "        return jsonify({\n"
    "            \"status\": \"healthy\",\n"
    "            \"uptime\": round(time.time() - security.start_time, 2),\n"
    "            \"total_requests\": security.total_requests,\n"
    "            \"blocked_requests\": security.blocked_requests,\n"
    "        }), 200"
)

if OLD_HEALTH in src:
    src = src.replace(OLD_HEALTH, NEW_HEALTH)
    print("[FIX-3] /health split ✅")
else:
    print("[WARN]  مش لاقي /health القديم")


# ── FIX-4 + FIX-6: Security headers ─────────────────────────────────────────
OLD_HEADERS = (
    "    @app.after_request\n"
    "    def after_request(response):\n"
    "        response.headers[\"X-Content-Type-Options\"]    = \"nosniff\"\n"
    "        response.headers[\"X-Frame-Options\"]           = \"DENY\"\n"
    "        response.headers[\"X-XSS-Protection\"]          = \"1; mode=block\"\n"
    "        response.headers[\"Strict-Transport-Security\"] = \"max-age=31536000; includeSubDomains\"\n"
    "        response.headers[\"Content-Security-Policy\"]   = \"default-src 'self'\"\n"
    "        response.headers[\"Referrer-Policy\"]           = \"strict-origin-when-cross-origin\"\n"
    "        return response"
)

NEW_HEADERS = (
    "    @app.after_request\n"
    "    def after_request(response):\n"
    "        # FIX-6: شيلنا X-XSS-Protection (deprecated 2019)\n"
    "        response.headers[\"X-Content-Type-Options\"]    = \"nosniff\"\n"
    "        response.headers[\"X-Frame-Options\"]           = \"DENY\"\n"
    "        response.headers[\"Strict-Transport-Security\"] = \"max-age=31536000; includeSubDomains\"\n"
    "        response.headers[\"Referrer-Policy\"]           = \"strict-origin-when-cross-origin\"\n"
    "        # FIX-4: CSP صح يسمح بـ React + CDN\n"
    "        response.headers[\"Content-Security-Policy\"] = (\n"
    "            \"default-src 'self'; \"\n"
    "            \"script-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; \"\n"
    "            \"style-src 'self' 'unsafe-inline' fonts.googleapis.com cdn.jsdelivr.net; \"\n"
    "            \"font-src 'self' fonts.gstatic.com data:; \"\n"
    "            \"img-src 'self' data: blob:; \"\n"
    "            \"connect-src 'self' http://127.0.0.1:5000 http://127.0.0.1:8070 \"\n"
    "            \"http://localhost:5000 http://localhost:8070; \"\n"
    "            \"frame-ancestors 'none';\"\n"
    "        )\n"
    "        # FIX-6: أضفنا Permissions-Policy الحديث\n"
    "        response.headers[\"Permissions-Policy\"] = \"geolocation=(), microphone=(), camera=()\"\n"
    "        return response"
)

if OLD_HEADERS in src:
    src = src.replace(OLD_HEADERS, NEW_HEADERS)
    print("[FIX-4+6] Security headers ✅")
else:
    print("[WARN]    مش لاقي after_request القديم")


# ── حفظ الملف ──────────────────────────────────────────────────────────────
if src != original:
    TARGET.write_text(src, encoding="utf-8")
    print(f"\n[DONE] تم تعديل {TARGET} بنجاح 🎉")
else:
    print("\n[INFO] مفيش تغييرات")
