"""
Dobby — Smart NLP Security Assistant for Virex
================================================
No external APIs. No internet. Pure Python.

How it works:
  1. Normalize input  → strip, lowercase, remove noise
  2. Intent scoring   → each intent has a wide bank of triggers
                        (exact keywords + fuzzy similarity)
  3. Pick best intent → highest score wins
  4. Build response   → inject live dashboard data into templates
"""

import re
import time
import random
import difflib
from collections import defaultdict


# ══════════════════════════════════════════════════════════════════
#  INTENT DEFINITIONS
#  Each intent has:
#    "triggers" → list of phrases/words that signal this intent
#    "lang"     → 'ar', 'en', or 'both'
# ══════════════════════════════════════════════════════════════════

INTENTS = {

    # ── Identity ──────────────────────────────────────────────────
    "identity": {
        "triggers": [
            # EN
            "who are you", "what are you", "your name", "who is dobby",
            "introduce yourself", "tell me about yourself", "what do you do",
            "are you a bot", "are you ai", "are you human", "what is your purpose",
            "how do you work", "what can you do", "your role",
            # AR
            "مين انت", "انت مين", "اسمك ايه", "عرف نفسك", "اسمك",
            "انت بتعمل ايه", "ايه دورك", "هو انت مين", "انت روبوت",
            "انت ذكاء اصطناعي", "انت بشر", "ايه وظيفتك", "بتشتغل ازاي",
        ]
    },

    # ── Greeting ──────────────────────────────────────────────────
    "greeting": {
        "triggers": [
            # EN
            "hi", "hello", "hey", "good morning", "good evening", "good afternoon",
            "howdy", "whats up", "sup", "greetings", "yo", "hiya",
            # AR
            "هاي", "هلو", "مرحبا", "السلام عليكم", "اهلا", "اهلين",
            "صباح الخير", "مساء الخير", "ازيك", "هلا", "يسلمو", "وعليكم السلام",
            "اهلا وسهلا", "هايا", "يلا هاي",
        ]
    },

    # ── How are you ───────────────────────────────────────────────
    "how_are_you": {
        "triggers": [
            # EN
            "how are you", "how are you doing", "are you okay", "you alright",
            "hows it going", "how you doing", "you good", "everything okay",
            # AR
            "عامل ايه", "ازيك", "اخبارك ايه", "كيفك", "كيف حالك",
            "عامل كويس", "انت بخير", "ايه اخبارك", "تمام",
        ]
    },

    # ── Thanks ────────────────────────────────────────────────────
    "thanks": {
        "triggers": [
            # EN
            "thank you", "thanks", "thx", "ty", "appreciate it", "great job",
            "well done", "nice", "awesome", "perfect", "good job",
            # AR
            "شكرا", "شكراً", "تسلم", "عاش", "كتر خيرك", "يسلمو",
            "شكرا جزيلا", "ممتاز", "احسنت", "برافو", "جميل",
        ]
    },

    # ── System Status ─────────────────────────────────────────────
    "system_status": {
        "triggers": [
            # EN
            "system status", "status", "overview", "health", "dashboard",
            "whats happening", "how is the system", "current state",
            "system health", "network status", "security status",
            "show stats", "give me stats", "stats", "statistics",
            "summary", "report", "what is going on", "situation",
            "is the system safe", "is it safe", "are we safe",
            "under attack", "being attacked", "system secure",
            "how many attacks", "how many times attacked",
            "attacked today", "attacks today", "times attacked",
            # AR
            "الوضع ايه", "ايه الوضع", "احصائيات", "احصايات", "تقرير",
            "الحالة ايه", "ايه الحالة", "ملخص", "عرض الاحصائيات",
            "ايه اللي بيحصل", "الوضع الامني", "حالة النظام",
            "اخبار النظام", "ايه الاخبار", "اعطني احصائيات",
            "وريني الاحصائيات", "فيه ايه", "ايه في النظام",
            "عايز اعرف احوال", "احوال النظام", "النظام امن",
            "في هجمات", "بيتهاجم", "النظام بخير",
        ]
    },

    # ── SQL Injection ─────────────────────────────────────────────
    "sql_stats": {
        "triggers": [
            # EN
            "sql injection", "sql attacks", "sql", "injection attacks",
            "database attacks", "how many sql", "sql count",
            "sql injection attempts", "any sql",
            # AR
            "حقن sql", "هجمات sql", "كام sql", "اس كيو ال",
            "حقن قواعد البيانات", "هجمات قواعد البيانات",
            "كام هجمة sql", "في sql",
        ]
    },

    # ── XSS ───────────────────────────────────────────────────────
    "xss_stats": {
        "triggers": [
            # EN
            "xss", "cross site scripting", "script injection",
            "how many xss", "xss attacks", "xss attempts",
            # AR
            "xss", "اكس اس اس", "كام xss", "هجمات xss",
            "حقن سكريبت", "سكريبت injection",
        ]
    },

    # ── Brute Force ───────────────────────────────────────────────
    "brute_stats": {
        "triggers": [
            # EN
            "brute force", "brute", "login attempts", "password attacks",
            "how many brute", "failed logins", "password guessing",
            "failed login", "login failed", "wrong password",
            "password cracking", "tried to login", "tried to log in",
            # AR
            "بروت فورس", "تخمين كلمة السر", "محاولات تسجيل الدخول",
            "هجمات كلمة المرور", "كام brute", "تخمين باسورد",
            "محاولات دخول", "هجمات دخول", "حاول يخش",
            "محاولات كلمة السر", "كام واحد حاول يدخل",
        ]
    },

    # ── Scanner ───────────────────────────────────────────────────
    "scanner_stats": {
        "triggers": [
            # EN
            "scanner", "scanning", "port scan", "vulnerability scan",
            "how many scans", "reconnaissance", "recon", "probing",
            # AR
            "سكانر", "فحص", "مسح", "كام فحص", "عمليات فحص",
            "هجمات فحص", "استطلاع",
        ]
    },

    # ── Rate Limit ────────────────────────────────────────────────
    "ratelimit_stats": {
        "triggers": [
            # EN
            "rate limit", "rate limiting", "dos", "ddos",
            "too many requests", "flooding", "how many rate",
            # AR
            "rate limit", "حد الطلبات", "هجوم dos", "طوفان طلبات",
            "ضغط على السيرفر", "كام rate limit",
        ]
    },

    # ── ML Detections ─────────────────────────────────────────────
    "ml_stats": {
        "triggers": [
            # EN
            "ml detection", "machine learning", "ml", "ai detection",
            "anomaly detection", "how many ml", "ml caught", "model",
            # AR
            "كشف ml", "تعلم آلي", "الموديل", "نموذج ml",
            "كام ml", "الذكاء الاصطناعي كشف", "كشف تلقائي",
        ]
    },

    # ── Top Attacker ──────────────────────────────────────────────
    "top_attacker": {
        "triggers": [
            # EN
            "top attacker", "most attacks", "worst ip", "dangerous ip",
            "who attacked most", "top ip", "highest threat",
            "most dangerous", "repeat attacker", "most frequent",
            # AR
            "اخطر ip", "اخطر مهاجم", "اكثر هجوم", "اكتر هجوم",
            "اشد خطورة", "اي بي اخطر", "مين بيهاجم اكتر",
            "اكثر مصدر تهديد", "اخطر عنوان",
        ]
    },

    # ── Recent Threats ────────────────────────────────────────────
    "recent_threats": {
        "triggers": [
            # EN
            "recent threats", "latest threats", "last attack", "latest attack",
            "what happened", "recent events", "recent attacks",
            "show threats", "list threats", "any new attacks",
            "what was the last", "recent incidents",
            "any suspicious", "suspicious activity", "anything suspicious",
            "new threats", "show me threats", "what threats", "any attacks",
            "new attacks", "anything new", "latest events",
            # AR
            "اخر هجمة", "اخر تهديد", "ايه اخر حاجة", "اخر هجمات",
            "ايه اللي اتكشف", "التهديدات الاخيرة", "اخر الاحداث",
            "عرض التهديدات", "في هجمات حديثة", "ايه اخر واحدة",
            "في حاجة مريبة", "في نشاط غريب", "هجمات جديدة",
            "ايه الجديد", "اي هجمات", "فيه هجمات",
        ]
    },

    # ── Incident Analysis ─────────────────────────────────────────
    "incident_why": {
        "triggers": [
            # EN
            "why", "reason", "explain", "analysis",
            "analyze this", "why this", "what caused", "describe",
            "tell me about", "what is this", "details",
            "analyze threats", "analyze the threats", "analyze attacks",
            # AR
            "ليه", "سبب", "شرح", "ايه السبب", "فسرلي",
            "تحليل", "حلل", "وضحلي", "ايه ده", "تفاصيل", "حصل ايه",
            "حلل التهديدات", "حلل الهجمات", "ممكن تحلل",
        ]
    },

    # ── Incident Action ───────────────────────────────────────────
    "incident_action": {
        "triggers": [
            # EN
            "what to do", "recommended action", "how to fix", "block it",
            "should i block", "next step", "recommendation", "fix",
            "what should i do", "how to handle", "response",
            "what do i do about", "how do i handle", "deal with",
            "what should we do", "action to take", "how to respond",
            "what should i do about these threats",
            # AR
            "اعمل ايه", "ايه الحل", "كيف احل", "بلوك", "احجب",
            "نصيحتك ايه", "ايه اللي اعمله", "الخطوة الجاية",
            "كيفية التعامل", "توصية", "ازاي اتعامل",
            "ايه اللازم اعمله", "كيف اتعامل",
        ]
    },

    # ── Security Tips ─────────────────────────────────────────────
    "security_tips": {
        "triggers": [
            # EN
            "security tips", "how to improve security", "best practices",
            "recommendations", "how to protect", "security advice",
            "strengthen security", "secure the system", "improve protection",
            # AR
            "نصايح امنية", "كيف احسن الامان", "افضل ممارسات",
            "كيف احمي النظام", "توصيات امنية", "تحسين الامان",
            "نصيحة امنية", "حماية النظام",
        ]
    },

    # ── Goodbye ───────────────────────────────────────────────────
    "goodbye": {
        "triggers": [
            # EN
            "bye", "goodbye", "see you", "later", "take care",
            "cya", "farewell", "good night", "good bye",
            # AR
            "باي", "مع السلامة", "وداعا", "اشوفك", "تصبح على خير",
            "يلا باي", "سلام",
        ]
    },
}


def _normalize(text: str) -> str:
    """Lowercase, remove punctuation, normalize Arabic chars."""
    text = text.lower().strip()
    # Remove common punctuation
    text = re.sub(r'[؟?!.,،;:\-_"\'()]', ' ', text)
    # Normalize Arabic alef variants
    text = re.sub(r'[أإآا]', 'ا', text)
    # Normalize teh marbuta
    text = re.sub(r'ة', 'ه', text)
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def _intent_score(query_norm: str, triggers: list) -> float:
    """
    Score how well query matches this intent.
    Combines:
      - exact substring match  (weight 1.0)
      - token-level match      (weight 0.8)
      - fuzzy similarity       (weight 0.6)
    Returns score 0.0 → 1.0
    """
    best = 0.0
    q_tokens = set(query_norm.split())

    for trigger in triggers:
        t_norm = _normalize(trigger)
        t_tokens = set(t_norm.split())

        # Exact substring
        if t_norm in query_norm or query_norm in t_norm:
            best = max(best, 1.0)
            continue

        # Token overlap ratio
        if t_tokens and q_tokens:
            overlap = len(q_tokens & t_tokens) / max(len(t_tokens), 1)
            best = max(best, overlap * 0.85)

        # Fuzzy similarity on full string
        ratio = difflib.SequenceMatcher(None, query_norm, t_norm).ratio()
        best = max(best, ratio * 0.7)

    return best


def _classify(query: str, threshold: float = 0.30) -> str:
    """Return the best-matching intent name, or 'unknown'."""
    q_norm = _normalize(query)
    scores = {}
    for intent_name, intent_data in INTENTS.items():
        scores[intent_name] = _intent_score(q_norm, intent_data["triggers"])

    best_intent = max(scores, key=scores.get)
    if scores[best_intent] >= threshold:
        return best_intent
    return "unknown"


# ══════════════════════════════════════════════════════════════════
#  CHATBOT CLASS
# ══════════════════════════════════════════════════════════════════

class SecurityChatbot:
    """
    Dobby — Smart NLP Security Assistant.
    Uses intent classification + fuzzy matching.
    No external APIs required.
    """

    def __init__(self, dashboard_ref):
        self.dashboard = dashboard_ref
        try:
            # Try new structure first
            from app.auth.roles import Role
            self.Role = Role
        except ImportError:
            # Fallback to root structure
            from roles import Role
            self.Role = Role

    # ── Language Detection ────────────────────────────────────────
    def _lang(self, text: str) -> str:
        return 'ar' if any('\u0600' <= c <= '\u06FF' for c in text) else 'en'

    # ── Response Builders ─────────────────────────────────────────

    def _r_identity(self, lang):
        if lang == 'ar':
            return random.choice([
                "أنا **Dobby** 🛡️ — مساعدك الأمني في Virex.\nبحلل الهجمات، بديك إحصائيات، وبساعدك تاخد القرار الصح.",
                "اسمي **Dobby**، المساعد الأمني الخاص بنظام Virex.\nاسألني عن أي هجمة أو تهديد وهرد عليك.",
                "معاك **Dobby** من Virex 🛡️\nاقدر أحلل التهديدات، أعطيك إحصائيات مباشرة، وأوصيك بالخطوات الصح.",
            ])
        return random.choice([
            "I'm **Dobby** 🛡️ — Virex's Security Assistant.\nI analyze threats, provide live stats, and help you make the right call.",
            "Name's **Dobby**. I'm the security assistant built into Virex.\nAsk me anything about attacks, incidents, or system health.",
            "Hey! I'm **Dobby**, your Virex security companion 🛡️\nI can analyze threats, show stats, and guide your response.",
        ])

    def _r_greeting(self, lang):
        if lang == 'ar':
            return random.choice([
                "أهلاً! 👋 معاك Dobby. إيه اللي تحب تعرفه عن النظام؟",
                "يا هلا! أنا Dobby جاهز. اسألني عن أي تهديد أو هجمة. 🛡️",
                "مرحباً بيك! 👋 Dobby في الخدمة. إيه اللي تحتاجه؟",
            ])
        return random.choice([
            "Hey there! 👋 Dobby here. What would you like to know about the system?",
            "Hello! I'm Dobby, ready to help. Ask me about any threat or attack. 🛡️",
            "Hi! Dobby at your service 👋 What can I help you with?",
        ])

    def _r_how_are_you(self, lang):
        s = self.dashboard.stats
        if lang == 'ar':
            return f"أنا تمام، والنظام شغال! 💪\nحالياً بتابع **{s.get('total_requests',0)}** طلب وحجبت **{s.get('blocked_requests',0)}** هجمة."
        return f"All good, system is running! 💪\nCurrently monitoring **{s.get('total_requests',0)}** requests with **{s.get('blocked_requests',0)}** blocked."

    def _r_thanks(self, lang):
        if lang == 'ar':
            return random.choice([
                "العفو! 🫡 أنا دايماً في الخدمة.",
                "يسعدني! لو في أي حاجة تانية قولي. 👍",
                "زي الفل! عرفني لو احتجت حاجة. 🛡️",
            ])
        return random.choice([
            "You're welcome! 🫡 Always here to help.",
            "Happy to help! Let me know if you need anything else. 👍",
            "Anytime! Stay secure. 🛡️",
        ])

    def _r_status(self, lang):
        s = self.dashboard.stats
        blocked_pct = 0
        if s.get('total_requests', 0) > 0:
            blocked_pct = round(s['blocked_requests'] / s['total_requests'] * 100, 1)

        if lang == 'ar':
            return (
                f"**📊 تقرير حالة النظام:**\n\n"
                f"🔵 إجمالي الطلبات : **{s.get('total_requests',0)}**\n"
                f"🔴 محجوب           : **{s.get('blocked_requests',0)}** ({blocked_pct}%)\n"
                f"🤖 كشف ML          : **{s.get('ml_detections',0)}**\n"
                f"💉 SQL Injection    : **{s.get('sql_injection_attempts',0)}**\n"
                f"🖥️ XSS             : **{s.get('xss_attempts',0)}**\n"
                f"🔑 Brute Force      : **{s.get('brute_force_attempts',0)}**\n"
                f"🔍 Scanner          : **{s.get('scanner_attempts',0)}**\n"
                f"⏱️ Rate Limit       : **{s.get('rate_limit_hits',0)}**"
            )
        return (
            f"**📊 System Status Report:**\n\n"
            f"🔵 Total Requests : **{s.get('total_requests',0)}**\n"
            f"🔴 Blocked        : **{s.get('blocked_requests',0)}** ({blocked_pct}%)\n"
            f"🤖 ML Detections  : **{s.get('ml_detections',0)}**\n"
            f"💉 SQL Injection   : **{s.get('sql_injection_attempts',0)}**\n"
            f"🖥️ XSS            : **{s.get('xss_attempts',0)}**\n"
            f"🔑 Brute Force     : **{s.get('brute_force_attempts',0)}**\n"
            f"🔍 Scanner         : **{s.get('scanner_attempts',0)}**\n"
            f"⏱️ Rate Limit      : **{s.get('rate_limit_hits',0)}**"
        )

    def _r_attack_stat(self, intent, lang):
        s = self.dashboard.stats
        mapping = {
            "sql_stats":      (s.get('sql_injection_attempts', 0), "SQL Injection",        "حقن SQL"),
            "xss_stats":      (s.get('xss_attempts', 0),           "XSS",                  "XSS"),
            "brute_stats":    (s.get('brute_force_attempts', 0),    "Brute Force",          "Brute Force"),
            "scanner_stats":  (s.get('scanner_attempts', 0),        "Scanner",              "فحص"),
            "ratelimit_stats":(s.get('rate_limit_hits', 0),         "Rate Limit",           "Rate Limit"),
            "ml_stats":       (s.get('ml_detections', 0),           "ML Anomaly Detection", "كشف ML"),
        }
        count, name_en, name_ar = mapping[intent]
        if lang == 'ar':
            return f"🛡️ رصدنا **{count}** محاولة {name_ar} لحد دلوقتي."
        return f"🛡️ Detected **{count}** {name_en} attempts so far."

    def _r_top_attacker(self, lang, is_admin):
        top = self.dashboard.get_top_attackers(3)
        if not top:
            return ("لسه مفيش هجمات مسجلة. 🟢" if lang == 'ar'
                    else "No attacks recorded yet. 🟢")
        lines = []
        for i, (ip, count) in enumerate(top, 1):
            ip_d = ip if is_admin else "XXX.XXX.XXX.XXX"
            lines.append(f"{i}. `{ip_d}` — **{count}** محاولة" if lang == 'ar'
                         else f"{i}. `{ip_d}` — **{count}** attempts")
        header = "🚨 **أخطر المصادر:**\n" if lang == 'ar' else "🚨 **Top Attackers:**\n"
        return header + "\n".join(lines)

    def _r_recent_threats(self, lang, is_admin):
        recent = list(self.dashboard.recent_threats)[-5:]
        if not recent:
            return ("مفيش تهديدات حديثة. 🟢" if lang == 'ar'
                    else "No recent threats. 🟢")
        header = "🔥 **آخر التهديدات:**\n" if lang == 'ar' else "🔥 **Recent Threats:**\n"
        lines = []
        for t in reversed(recent):
            ip_d = t.get('ip', '?') if is_admin else "XXX.XXX.XXX.XXX"
            lines.append(
                f"• `{t.get('timestamp','?')}` — **{t.get('type','?')}** "
                f"من {ip_d} ({t.get('severity','?')})"
                if lang == 'ar' else
                f"• `{t.get('timestamp','?')}` — **{t.get('type','?')}** "
                f"from {ip_d} ({t.get('severity','?')})"
            )
        return header + "\n".join(lines)

    def _r_security_tips(self, lang):
        if lang == 'ar':
            return (
                "**💡 نصايح أمنية عامة:**\n\n"
                "1. 🔒 غيّر الـ passwords الافتراضية فوراً\n"
                "2. 🛡️ فعّل الـ Rate Limiting على كل الـ endpoints\n"
                "3. 📋 راجع الـ logs بشكل دوري\n"
                "4. 🚫 اعمل block للـ IPs اللي بتهاجم بشكل متكرر\n"
                "5. 🔄 حدّث الـ ML model بانتظام على بيانات جديدة\n"
                "6. ⚡ فعّل التنبيهات الفورية للهجمات الحرجة"
            )
        return (
            "**💡 Security Best Practices:**\n\n"
            "1. 🔒 Change all default passwords immediately\n"
            "2. 🛡️ Enable Rate Limiting on all endpoints\n"
            "3. 📋 Review logs regularly\n"
            "4. 🚫 Block IPs with repeated attack attempts\n"
            "5. 🔄 Retrain the ML model with fresh data periodically\n"
            "6. ⚡ Enable real-time alerts for critical attacks"
        )

    def _r_incident_why(self, inc, lang, is_admin):
        ip_d = inc.source_ip if is_admin else "XXX.XXX.XXX.XXX"
        payload_d = (inc.events[0].get('snippet', '')[:40] if is_admin else "[HIDDEN]") if inc.events else "N/A"
        if lang == 'ar':
            return (
                f"**🔍 تحليل الحادثة:**\n\n"
                f"• النوع      : **{inc.category}**\n"
                f"• المصدر     : `{ip_d}`\n"
                f"• الخطورة    : **{inc.severity}**\n"
                f"• الحالة     : {inc.status}\n"
                f"• Payload    : `{payload_d}`\n\n"
                f"ده غالباً هجوم بيحاول يستغل ثغرة في النظام. "
                f"عدد المحاولات: **{len(inc.events)}**."
            )
        return (
            f"**🔍 Incident Analysis:**\n\n"
            f"• Type     : **{inc.category}**\n"
            f"• Source   : `{ip_d}`\n"
            f"• Severity : **{inc.severity}**\n"
            f"• Status   : {inc.status}\n"
            f"• Payload  : `{payload_d}`\n\n"
            f"This is likely an exploit attempt targeting a system vulnerability. "
            f"Total attempts: **{len(inc.events)}**."
        )

    def _r_incident_action(self, inc, lang, is_admin):
        ip_d = inc.source_ip if is_admin else "هذا المصدر"
        if lang == 'ar':
            return (
                f"**⚡ توصيات Dobby:**\n\n"
                f"1. **احجب {ip_d}** فوراً من صفحة الـ Incidents\n"
                f"2. راجع سجلات السيرفر للتأكد مفيش حاجة اتسربت\n"
                f"3. لو كانت False Positive، سجلها وأغلق الحادثة\n"
                f"4. لو الهجوم مستمر، فعّل Rate Limiting أقوى\n"
                f"5. حدّث الـ ML model لو النمع ده جديد"
            )
        ip_d = inc.source_ip if is_admin else "this source"
        return (
            f"**⚡ Dobby Recommendations:**\n\n"
            f"1. **Block {ip_d}** immediately from the Incidents page\n"
            f"2. Review server logs to confirm no data was breached\n"
            f"3. If it's a False Positive, mark and close the incident\n"
            f"4. If attacks persist, tighten Rate Limiting\n"
            f"5. Retrain the ML model if this is a new attack pattern"
        )

    def _r_goodbye(self, lang):
        if lang == 'ar':
            return random.choice([
                "مع السلامة! 👋 Dobby دايماً هنا لو احتجت.",
                "باي! 🛡️ النظام تحت المراقبة.",
                "تصبح على خير! Dobby يراقب كل حاجة. 😎",
            ])
        return random.choice([
            "Goodbye! 👋 Dobby is always here if you need.",
            "See you! 🛡️ System stays monitored.",
            "Take care! Dobby keeps watching. 😎",
        ])

    def _r_unknown(self, lang):
        if lang == 'ar':
            return random.choice([
                "مش فاهم قصدك كويس. 🤔\nاقدر أساعدك في:\n• إحصائيات الهجمات\n• تحليل الحوادث\n• التوصيات الأمنية\n• حالة النظام",
                "ممكن توضح أكتر؟ اقدر أجاوب على أسئلة الأمان والنظام. 🛡️",
                "مش متأكد من قصدك. جرب تسألني عن الهجمات أو الإحصائيات أو الحوادث.",
            ])
        return random.choice([
            "I'm not sure what you mean. 🤔\nI can help with:\n• Attack statistics\n• Incident analysis\n• Security recommendations\n• System status",
            "Could you clarify? I handle security questions, stats, and incident analysis. 🛡️",
            "Not quite sure. Try asking about attacks, incidents, or system health.",
        ])

    # ── Main Entry ────────────────────────────────────────────────

    def generate_response(
        self,
        user_query:  str,
        incident_id: str  = None,
        page_context       = None,
        history:     list = None,
        role:        str  = "user",
    ) -> str:

        time.sleep(0.2)
        lang     = self._lang(user_query)
        is_admin = (role == self.Role.ADMIN)
        intent   = _classify(user_query)

        # ── non-admin: block sensitive queries ──────────────────
        if not is_admin and intent in ("top_attacker",) and not incident_id:
            if lang == 'ar':
                return "عذراً، التفاصيل دي للمسؤولين فقط. 🔒"
            return "Sorry, this information is restricted to admins. 🔒"

        # ── simple intents ───────────────────────────────────────
        if intent == "identity":       return self._r_identity(lang)
        if intent == "greeting":       return self._r_greeting(lang)
        if intent == "how_are_you":    return self._r_how_are_you(lang)
        if intent == "thanks":         return self._r_thanks(lang)
        if intent == "goodbye":        return self._r_goodbye(lang)
        if intent == "system_status":  return self._r_status(lang)
        if intent == "top_attacker":   return self._r_top_attacker(lang, is_admin)
        if intent == "recent_threats": return self._r_recent_threats(lang, is_admin)
        if intent == "security_tips":  return self._r_security_tips(lang)

        # ── attack type stats ────────────────────────────────────
        if intent in ("sql_stats", "xss_stats", "brute_stats",
                      "scanner_stats", "ratelimit_stats", "ml_stats"):
            return self._r_attack_stat(intent, lang)

        # ── incident_action without incident → security tips ─────
        if intent == "incident_action" and not incident_id:
            return self._r_security_tips(lang)

        # ── incident_why without incident → recent threats ───────
        if intent == "incident_why" and not incident_id:
            return self._r_recent_threats(lang, is_admin)

        # ── incident-specific ────────────────────────────────────
        if incident_id:
            inc = self.dashboard.incidents.get(incident_id)
            if not inc:
                return ("الحادثة دي مش موجودة في السجلات." if lang == 'ar'
                        else "This incident was not found in records.")
            if intent == "incident_why":    return self._r_incident_why(inc, lang, is_admin)
            if intent == "incident_action": return self._r_incident_action(inc, lang, is_admin)
            # fallback for incident page: give full summary
            return self._r_incident_why(inc, lang, is_admin)

        # ── unknown ──────────────────────────────────────────────
        return self._r_unknown(lang)