"""
VIREX Payload Analyzer — Fully local attack detection and explanation engine.
No external APIs. Pure Python regex + heuristics.
"""

import re

ATTACK_PATTERNS = {
    "SQL Injection": {
        "severity": "🔴 Critical",
        "patterns": [
            r"'.*?--", r"'.*?#", r"'.*?;", r"1\s*=\s*1", r"1\s*=\s*0",
            r"union\s+select", r"union\s+all\s+select", r"select\s+.*?\s+from",
            r"or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", r"and\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            r"drop\s+table", r"drop\s+database", r"truncate\s+table",
            r"insert\s+into", r"delete\s+from", r"update\s+.*?\s+set",
            r"exec\s*\(", r"execute\s*\(", r"xp_cmdshell", r"sp_executesql",
            r"sleep\s*\(\d+", r"waitfor\s+delay", r"benchmark\s*\(",
            r"information_schema", r"@@version", r"@@hostname",
        ],
    },
    "XSS (Cross-Site Scripting)": {
        "severity": "🟠 High",
        "patterns": [
            r"<script[^>]*>", r"<\/script>", r"javascript\s*:", r"onerror\s*=",
            r"onload\s*=", r"onclick\s*=", r"onmouseover\s*=", r"onfocus\s*=",
            r"alert\s*\(", r"confirm\s*\(", r"prompt\s*\(", r"document\.cookie",
            r"document\.location", r"window\.location", r"fetch\s*\(",
            r"<img[^>]*onerror", r"<svg[^>]*onload", r"<iframe[^>]*src",
            r"eval\s*\(", r"fromCharCode", r"<[^>]*on\w+\s*=",
        ],
    },
    "CSRF (Cross-Site Request Forgery)": {
        "severity": "🟡 Medium",
        "patterns": [
            r"origin\s*:\s*https?://.*?[^v]irex", r"referer\s*:\s*https?://.*?[^v]irex",
            r"x-csrf-token\s*:\s*null", r"x-csrf-token\s*:\s*invalid",
            r"csrf.*?bypass", r"csrf.*?token.*?missing",
        ],
    },
    "SSRF (Server-Side Request Forgery)": {
        "severity": "🟠 High",
        "patterns": [
            r"http://127\.0\.0\.1", r"http://localhost", r"http://169\.254\.169\.254",
            r"http://0\.0\.0\.0", r"http://10\.\d+\.\d+\.\d+",
            r"http://172\.1[6-9]\.", r"http://172\.2[0-9]\.", r"http://172\.3[0-1]\.",
            r"http://192\.168\.", r"file:///", r"gopher://", r"dict://",
            r"metadata\.google\.internal", r"metadata\.amazonaws\.com",
        ],
    },
    "Command Injection": {
        "severity": "🔴 Critical",
        "patterns": [
            r";\s*\w+\s", r"\|\s*\w+\s", r"`.*?`", r"\$\(.*?\)",
            r"&&\s*\w+", r"\|\|\s*\w+", r">\s*/tmp/", r">\s*/dev/",
            r"cat\s+/etc/passwd", r"ls\s+-la", r"whoami", r"id\s*;",
            r"rm\s+-rf", r"wget\s+http", r"curl\s+http", r"chmod\s+777",
            r"ping\s+-c", r"nslookup", r"traceroute", r"nc\s+-e",
        ],
    },
    "Path Traversal": {
        "severity": "🟠 High",
        "patterns": [
            r"\.\./\.\./", r"\.\.\\\.\.\\", r"\.\./", r"\.\.\\",
            r"\.\.%2f", r"\.\.%5c", r"%2e%2e%2f", r"%2e%2e%5c",
            r"etc/passwd", r"etc/shadow", r"windows\\system32",
            r"boot\.ini", r"win\.ini", r"\.env", r"\.git/config",
        ],
    },
    "Brute Force": {
        "severity": "🟡 Medium",
        "patterns": [
            r"login.*?admin", r"password.*?123", r"admin.*?admin",
            r"wordlist", r"hydra", r"medusa", r"john.*?ripper",
            r"burp.*?intruder", r"repeated.*?login", r"credential.*?stuffing",
        ],
    },
    "Rate Limit / DoS": {
        "severity": "🟡 Medium",
        "patterns": [
            r"x-forwarded-for.*?\d+\.\d+\.\d+\.\d+", r"user-agent.*?slowloris",
            r"user-agent.*?goldeneye", r"user-agent.*?hulk",
            r"keep-alive.*?timeout", r"connection.*?keep-alive",
        ],
    },
    "Scanner / Recon": {
        "severity": "🟢 Low",
        "patterns": [
            r"nikto", r"nmap", r"gobuster", r"dirbuster", r"wfuzz",
            r"sqlmap", r"acunetix", r"nessus", r"openvas", r"burp suite",
            r"zap", r"arachni", r"wpscan", r"joomscan",
        ],
    },
    "ML Anomaly Detection": {
        "severity": "🟠 High",
        "patterns": [
            r"ml_detected.*?true", r"confidence.*?0\.[89]\d", r"anomaly.*?detected",
            r"unusual.*?pattern", r"unexpected.*?payload", r"abnormal.*?request",
        ],
    },
}


def analyze_payload(text: str) -> dict | None:
    """
    Analyze a raw text (log, payload, URL, description) and detect attack types.
    Returns a structured dict with attack info, or None if nothing is detected.
    """
    if not text or not isinstance(text, str):
        return None

    text_lower = text.lower()
    results = []

    for attack_name, attack_info in ATTACK_PATTERNS.items():
        for pattern in attack_info["patterns"]:
            if re.search(pattern, text_lower, re.IGNORECASE):
                results.append({
                    "attack": attack_name,
                    "severity": attack_info["severity"],
                    "matched_pattern": pattern,
                })
                break

    if not results:
        return None

    # Deduplicate by attack name, keep highest severity
    seen = set()
    unique = []
    for r in results:
        if r["attack"] not in seen:
            seen.add(r["attack"])
            unique.append(r)

    return {
        "detections": unique,
        "total": len(unique),
        "highest_severity": _highest_severity(unique),
        "is_malicious": any(
            "Critical" in r["severity"] or "High" in r["severity"]
            for r in unique
        ),
    }


def _highest_severity(detections: list) -> str:
    order = ["🔴 Critical", "🟠 High", "🟡 Medium", "🟢 Low"]
    for level in order:
        for d in detections:
            if level in d["severity"]:
                return level
    return "ℹ️ Info"


def generate_analysis_response(
    analysis: dict,
    user_text: str,
    lang: str = "en",
) -> str:
    """Generate a human-readable analysis response from the analysis result."""
    detections = analysis["detections"]

    if lang == "ar":
        lines = [
            "**🔍 تحليل Dobby:**\n",
            f"تم اكتشاف **{len(detections)}** نوع هجوم في النص اللي أرسلته:\n",
        ]
        for d in detections:
            lines.append(f"{d['severity']} **{d['attack']}**")
        lines.append("")

        if analysis["is_malicious"]:
            lines.append("⚠️ النص ده **خبيث** ويشكل خطر على النظام.\n")
        else:
            lines.append("✅ النص ده مش خطير لكن لازم تراقبه.\n")

        # Detailed explanation per attack
        for d in detections:
            lines.append(f"**{d['attack']}**")
            lines.append(_explain_attack_ar(d["attack"]))
            lines.append(_remediation_ar(d["attack"]))
            lines.append("")

        lines.append("📌 لو عايز تفاصيل أكتر، اسألني!")
        return "\n".join(lines)

    lines = [
        "**🔍 Dobby Analysis:**\n",
        f"Detected **{len(detections)}** attack type(s) in the provided text:\n",
    ]
    for d in detections:
        lines.append(f"{d['severity']} **{d['attack']}**")
    lines.append("")

    if analysis["is_malicious"]:
        lines.append("⚠️ This content is **malicious** and poses a risk to the system.\n")
    else:
        lines.append("✅ This content is not critical but should be monitored.\n")

    for d in detections:
        lines.append(f"**{d['attack']}**")
        lines.append(_explain_attack_en(d["attack"]))
        lines.append(_remediation_en(d["attack"]))
        lines.append("")

    lines.append("📌 Need more details? Just ask!")
    return "\n".join(lines)


def generate_payload_info(payload: str, lang: str = "en") -> str:
    """Generate a short, direct analysis of a payload snippet."""
    analysis = analyze_payload(payload)
    if not analysis:
        if lang == "ar":
            return "ℹ️ مفيش هجوم واضح في النص ده."
        return "ℹ️ No obvious attack pattern detected in this text."
    return generate_analysis_response(analysis, payload, lang)


def _explain_attack_en(attack: str) -> str:
    explanations = {
        "SQL Injection": (
            "How it works: Attacker injects malicious SQL queries through input fields "
            "to manipulate your database — reading, modifying, or deleting data."
        ),
        "XSS (Cross-Site Scripting)": (
            "How it works: Attacker injects client-side scripts (usually JavaScript) "
            "into web pages viewed by other users, stealing sessions or defacing pages."
        ),
        "CSRF (Cross-Site Request Forgery)": (
            "How it works: Attacker tricks an authenticated user into performing "
            "unwanted actions on a web application where they're logged in."
        ),
        "SSRF (Server-Side Request Forgery)": (
            "How it works: Attacker makes the server send requests to internal resources "
            "(localhost, cloud metadata services) to extract sensitive info."
        ),
        "Command Injection": (
            "How it works: Attacker executes arbitrary OS commands on the server "
            "through vulnerable input fields, gaining shell access."
        ),
        "Path Traversal": (
            "How it works: Attacker uses `../` sequences to escape the web root "
            "and read sensitive files like `/etc/passwd` or `.env`."
        ),
        "Brute Force": (
            "How it works: Automated tool tries thousands of username/password "
            "combinations to gain unauthorized access."
        ),
        "Rate Limit / DoS": (
            "How it works: Overwhelms server resources by sending excessive requests, "
            "causing denial of service for legitimate users."
        ),
        "Scanner / Recon": (
            "How it works: Automated scanning tools probe the application "
            "to discover vulnerabilities, endpoints, and configurations."
        ),
        "ML Anomaly Detection": (
            "How it works: The Random Forest model flagged this request as anomalous "
            "based on TF-IDF features that deviate from normal traffic patterns."
        ),
    }
    return explanations.get(attack, "")


def _explain_attack_ar(attack: str) -> str:
    explanations = {
        "SQL Injection": (
            "إزاي بيشتغل: المهاجم بيحقن أوامر SQL خبيثة جوه المدخلات "
            "عشان يتلاعب بقاعدة البيانات — يقرا، يعدل، أو يمسح البيانات."
        ),
        "XSS (Cross-Site Scripting)": (
            "إزاي بيشتغل: المهاجم بيحط كود جافاسكريبت خبيث جوه الصفحة "
            "اللي بيشوفها المستخدمين التانيين، عشان يسرق الجلسات أو يغير محتوى الموقع."
        ),
        "CSRF (Cross-Site Request Forgery)": (
            "إزاي بيشتغل: المهاجم بيخدع مستخدم مسجل يدخل عالموقع "
            "عشان يعمل إجراءات من غير ما يعرف (زي تغيير الباسورد)."
        ),
        "SSRF (Server-Side Request Forgery)": (
            "إزاي بيشتغل: المهاجم بيخلي السيرفر يبعت طلبات لموارد داخلية "
            "(زي localhost أو خدمات السحابة) عشان يسرق معلومات حساسة."
        ),
        "Command Injection": (
            "إزاي بيشتغل: المهاجم بينفذ أوامر نظام تشغيل على السيرفر "
            "عن طريق مدخلات غير مؤمنة، وده ممكن يخليه يتحكم في السيرفر كله."
        ),
        "Path Traversal": (
            "إزاي بيشتغل: المهاجم بيستخدم علامات `../` عشان يخرج من مجلد الموقع "
            "ويقرا ملفات حساسة زي ملفات كلمات السر أو الإعدادات."
        ),
        "Brute Force": (
            "إزاي بيشتغل: أدوات آلية بتجرب آلاف من تركيب الباسوردات "
            "عشان تخمن كلمة السر الصحيحة وتخش على الحساب."
        ),
        "Rate Limit / DoS": (
            "إزاي بيشتغل: غمر السيرفر بطلبات كثيرة جداً في وقت قصير "
            "عشان يوقف الخدمة عن المستخدمين الحقيقيين."
        ),
        "Scanner / Recon": (
            "إزاي بيشتغل: أدوات المسح الضوئي بتفحص التطبيق "
            "عشان تكتشف الثغرات ونقاط الضعف في النظام."
        ),
        "ML Anomaly Detection": (
            "إزاي بيشتغل: نموذج Random Forest صنف الطلب ده على أنه غير طبيعي "
            "بناءً على خصائص (TF-IDF) مختلفة عن نمط الحركة العادي."
        ),
    }
    return explanations.get(attack, "")


def _remediation_en(attack: str) -> str:
    remediations = {
        "SQL Injection": (
            "Fix: Use parameterized queries (SQLAlchemy), validate input, "
            "and apply strict WAF regex rules."
        ),
        "XSS (Cross-Site Scripting)": (
            "Fix: Sanitize all user input, use Content-Security-Policy headers, "
            "and escape HTML output with Jinja2 autoescaping."
        ),
        "CSRF (Cross-Site Request Forgery)": (
            "Fix: Use CSRF tokens (Flask-WTF), validate Origin/Referer headers, "
            "and set SameSite=Strict on cookies."
        ),
        "SSRF (Server-Side Request Forgery)": (
            "Fix: Block outbound requests to private IPs, validate URL schemas, "
            "and use a whitelist of allowed destinations."
        ),
        "Command Injection": (
            "Fix: Never pass user input to shell commands. Use subprocess with "
            "argument lists (not strings) and validate all input."
        ),
        "Path Traversal": (
            "Fix: Normalize file paths, block `../` sequences, "
            "and restrict file access to a specific directory."
        ),
        "Brute Force": (
            "Fix: Enable rate limiting on login, use account lockout after N attempts, "
            "and enforce strong passwords."
        ),
        "Rate Limit / DoS": (
            "Fix: Configure rate limiting (Flask-Limiter), use a CDN, "
            "and monitor traffic patterns for anomalies."
        ),
        "Scanner / Recon": (
            "Fix: Block known scanner User-Agents, monitor for probe patterns, "
            "and use IP reputation lists."
        ),
        "ML Anomaly Detection": (
            "Fix: Review the flagged request manually, check False Positive rate, "
            "and retrain the model if the pattern is legitimate."
        ),
    }
    return remediations.get(attack, "")


def _remediation_ar(attack: str) -> str:
    remediations = {
        "SQL Injection": (
            "الحل: استخدم parameterized queries (SQLAlchemy)، "
            "حقق من صحة المدخلات، وطبق قواعد WAF صارمة."
        ),
        "XSS (Cross-Site Scripting)": (
            "الحل: نظف كل المدخلات، استخدم Content-Security-Policy، "
            "وعطل تشغيل HTML من الـ Jinja2 autoescaping."
        ),
        "CSRF (Cross-Site Request Forgery)": (
            "الحل: استخدم توكن CSRF (Flask-WTF)، "
            "وتأكد من صحة الـ Origin/Referer headers."
        ),
        "SSRF (Server-Side Request Forgery)": (
            "الحل: امنع الطلبات للـ IPs الداخلية، "
            "وتأكد من صحة الـ URLs المسموح بها."
        ),
        "Command Injection": (
            "الحل: متستخدمش مدخلات المستخدم جوه أوامر الشيل. "
            "استخدم subprocess مع argument lists."
        ),
        "Path Traversal": (
            "الحل: رفض أي `../` في المسارات، "
            "وحصر الوصول للملفات في مجلد معين."
        ),
        "Brute Force": (
            "الحل: فعّل Rate Limiting على صفحة تسجيل الدخول، "
            "وقفل الحساب بعد عدد معين من المحاولات الفاشلة."
        ),
        "Rate Limit / DoS": (
            "الحل: استخدم Flask-Limiter، "
            "وراقب أنماط الحركة للكشف عن الحالات الشاذة."
        ),
        "Scanner / Recon": (
            "الحل: احجب User-Agents المعروفة لأدوات الفحص، "
            "واستخدم قوائم IPs المعروفة."
        ),
        "ML Anomaly Detection": (
            "الحل: راجع الطلب يدوياً، "
            "وحدّث الـ ML model لو النمط ده مش حقيقي."
        ),
    }
    return remediations.get(attack, "")
