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
import os
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
    
    # ── NEW KNOWLEDGE INTENTS ─────────────────────────────────────
    "what_is_sqli": {
        "triggers": ["what is sql injection", "explain sql", "يعني ايه sql", "شرح sql", "حقن قواعد بيانات", "sqli meaning", "ما هو sql", "sql injection"]
    },
    "what_is_xss": {
        "triggers": ["what is xss", "explain xss", "cross site scripting", "يعني ايه xss", "شرح xss", "ما هو xss"]
    },
    "what_is_ddos": {
        "triggers": ["what is ddos", "explain ddos", "dos attack", "denial of service", "يعني ايه ddos", "شرح ddos", "ما هو ddos", "حجب الخدمة", "طوفان"]
    },
    "what_is_malware": {
        "triggers": ["what is malware", "explain malware", "virus", "trojan", "ransomware", "يعني ايه فيروس", "برمجيات خبيثة", "فيروسات", "شرح malware"]
    },
    "what_is_phishing": {
        "triggers": ["what is phishing", "explain phishing", "social engineering", "يعني ايه تصيد", "شرح التصيد", "نصب", "احتيال", "phishing meaning"]
    },
    "what_is_firewall": {
        "triggers": ["what is firewall", "explain firewall", "waf", "يعني ايه جدار", "شرح جدار حماية", "ما هو الفايرول", "جدار ناري"]
    },
    "virex_info": {
        "triggers": ["what is virex", "who made virex", "virex info", "ايه هو فايركس", "مين عمل فايركس", "نظام virex", "معلومات عن virex", "فايركس"]
    },
    "dashboard_help": {
        "triggers": ["how to use", "help me", "dashboard guide", "ازاي استخدم الموقع", "شرح الموقع", "مساعدة", "استخدام الداشبورد", "لوحة التحكم", "كيف استخدم"]
    },
}

# --- EXTENDED EXISTING INTENTS FOR BETTER RECOGNITION ---
INTENTS["greeting"]["triggers"].extend(["عامل ايه يا دوبي", "يا دوبي", "صباحو", "مساءو", "hello dobby", "hi dobby", "ازيك يا دوبي"])
INTENTS["thanks"]["triggers"].extend(["حبيبي", "كفاءة", "الله ينور", "تسلم ايدك", "شكرا يا دوبي", "عظمة"])
INTENTS["identity"]["triggers"].extend(["انت مين يالا", "مين المطور بتاعك", "مين برمجك", "انت عبارة عن ايه", "عرفني عليك"])
INTENTS["incident_action"]["triggers"].extend(["تنصحني بايه", "اتصرف ازاي", "اعمل ايه مع الهجوم", "الحل ايه"])



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


STOP_WORDS = {"is", "are", "do", "does", "what", "how", "who", "tell", "me", "about", "can", "you", "the", "a", "an", "في", "ايه", "هو", "مين", "عن", "من", "هل", "بتاع", "يعني", "شرح", "وضح", "قولي"}

def _stem(word: str) -> str:
    if word.endswith('s') and len(word) > 3 and not word.endswith('ss'):
        return word[:-1]
    return word

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
    
    raw_q_tokens = query_norm.split()
    q_tokens = { _stem(w) for w in raw_q_tokens if w not in STOP_WORDS }

    for trigger in triggers:
        t_norm = _normalize(trigger)
        raw_t_tokens = t_norm.split()
        t_tokens = { _stem(w) for w in raw_t_tokens if w not in STOP_WORDS }

        # Exact substring
        if t_norm in query_norm or query_norm in t_norm:
            best = max(best, 1.0)
            continue

        # Token overlap ratio
        if t_tokens and q_tokens:
            overlap = len(q_tokens & t_tokens) / max(len(t_tokens), 1)
            # Boost score significantly if ALL non-stop tokens of the trigger are in the query
            if len(q_tokens & t_tokens) == len(t_tokens):
                best = max(best, 0.95)
            else:
                best = max(best, overlap * 0.85)

        # Fuzzy similarity on full string
        ratio = difflib.SequenceMatcher(None, query_norm, t_norm).ratio()
        best = max(best, ratio * 0.7)

    return best


def _classify(query: str, threshold: float = 0.20) -> str:
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
        if lang == 'ar':
            return "الحمد لله تمام! أنا هنا لمساعدتك على فهم التهديدات الأمنية أفضل."
        return "I'm doing well, thank you! I'm here to help you understand cyber threats better."

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

    def _r_what_is_sqli(self, lang):
        if lang == 'ar':
            return "**حقن قواعد البيانات (SQL Injection):**\nهو هجوم بيستغل ثغرات في الكود عشان ينفذ أوامر SQL خبيثة جوه قاعدة البيانات. المهاجم ممكن يسرق بيانات، يمسحها، أو حتى يتحكم في السيرفر!"
        return "**SQL Injection (SQLi):**\nAn attack that executes malicious SQL statements to manipulate database data, allowing attackers to view, modify, or delete restricted information."

    def _r_what_is_xss(self, lang):
        if lang == 'ar':
            return "**السكربتات العابرة للمواقع (XSS):**\nالمهاجم بيحط كود خبيث (زي جافاسكريبت) جوه صفحة ويب بيشوفها مستخدمين تانيين. ده بيسمحله يسرق الكوكيز أو يغير شكل الصفحة!"
        return "**Cross-Site Scripting (XSS):**\nA vulnerability where an attacker injects malicious scripts into trusted websites viewed by other users, often used to steal session cookies."

    def _r_what_is_ddos(self, lang):
        if lang == 'ar':
            return "**هجوم حجب الخدمة (DDoS):**\nالمهاجم بيبعت آلاف أو ملايين الطلبات الوهمية للسيرفر في نفس الوقت، عشان يخليه يقع أو يبطأ جداً وميقدرش يخدم المستخدمين الحقيقيين."
        return "**Distributed Denial of Service (DDoS):**\nA malicious attempt to disrupt normal traffic of a targeted server by overwhelming it with a flood of internet traffic."

    def _r_what_is_malware(self, lang):
        if lang == 'ar':
            return "**البرمجيات الخبيثة (Malware):**\nأي برنامج متصمم عشان يضر جهاز أو شبكة. بيشمل الفيروسات، حصان طروادة (Trojan)، وبرامج الفدية (Ransomware) اللي بتشفر ملفاتك."
        return "**Malware:**\nMalicious software designed to harm or exploit any programmable device or network, including viruses, trojans, and ransomware."

    def _r_what_is_phishing(self, lang):
        if lang == 'ar':
            return "**التصيد الاحتيالي (Phishing):**\nهجوم بيعتمد على خداعك (غالباً بإيميل أو رسالة مزيفة) عشان تدي المهاجم معلومات حساسة زي كلمات السر أو بيانات البنك."
        return "**Phishing:**\nA cybercrime in which a target is contacted by someone posing as a legitimate institution to lure them into providing sensitive data."

    def _r_what_is_firewall(self, lang):
        if lang == 'ar':
            return "**جدار الحماية (Firewall):**\nهو نظام أمني بيراقب ويتحكم في حركة المرور اللي داخلة وطالعة من الشبكة بناءً على قواعد محددة، عشان يمنع الهجمات. و Virex بيشتغل كجدار حماية ذكي!"
        return "**Firewall:**\nA network security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules. Virex acts as a smart WAF!"

    def _r_virex_info(self, lang):
        if lang == 'ar':
            return "**عن Virex 🛡️:**\nنظام لحماية التطبيقات (WAF) معتمد على الذكاء الاصطناعي لاكتشاف وصد الهجمات في الوقت الفعلي. تم تطويره كمشروع تخرج علشان يكون درع قوي ضد التهديدات السيبرانية!"
        return "**About Virex 🛡️:**\nAn AI-powered Web Application Firewall (WAF) designed to detect and block threats in real-time. Created as a graduation project to be a robust cyber shield!"

    def _r_dashboard_help(self, lang):
        if lang == 'ar':
            return "عشان تستخدم الداشبورد:\n1️⃣ **Incidents**: شوف الهجمات والحوادث المتسجلة.\n2️⃣ **Threats**: خريطة حية وتحليل للتهديدات.\n3️⃣ **Network**: راقب حركة المرور.\n4️⃣ **Settings**: لتعديل الحماية والـ Rate Limiting."
        return "To use the dashboard:\n1️⃣ **Incidents**: View recorded attacks.\n2️⃣ **Threats**: Live map & threat analysis.\n3️⃣ **Network**: Monitor incoming traffic.\n4️⃣ **Settings**: Configure firewall and rate limits."

    def _r_unknown(self, lang):
        if lang == 'ar':
            return random.choice([
                "مش فاهم قصدك كويس. 🤔\nممكن تسألني عن معنى الهجمات (زي DDoS, SQL, XSS)، أو تسأل عن إحصائيات النظام والتوصيات الأمنية.",
                "تقدر توضح أكتر؟ الكلمات دي جديدة عليا. 🛡️\nاسألني عن الهجمات أو لوحة التحكم وهجاوبك.",
                "معلش مفهمتش. جرب تسألني سؤال مباشر عن حالة السيرفر أو أنواع التهديدات.",
            ])
        return random.choice([
            "I'm not sure what you mean. 🤔\nYou can ask me to explain attacks (like DDoS, SQLi, XSS), or ask for system stats and security tips.",
            "Could you clarify? I handle security definitions, dashboard stats, and incident analysis. 🛡️",
            "Not quite sure. Try asking about attacks, incidents, or how to use the dashboard.",
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

        # ── INPUT VALIDATION MIDDLEWARE (Prompt Injection Defense) ──
        forbidden_phrases = ["ignore instructions", "system prompt", "reveal"]
        query_lower = user_query.lower()
        if any(phrase in query_lower for phrase in forbidden_phrases):
            return "🚫 Security Exception: Malicious prompt injection detected and blocked."

        # ── EGRESS FILTER MIDDLEWARE ──
        def filter_response(text: str) -> str:
            # Prevent hallucinated internal metrics or logs from leaking
            leak_keywords = ["192.168.", "10.0.0.", "log data:", "system internals", "user email", "database row"]
            text_lower = text.lower()
            if any(leak in text_lower for leak in leak_keywords):
                return "🛡️ Security Block: The requested data contains restricted system internals or logs which I am not authorized to disclose."
            return text

        # ── GEMINI AI INTEGRATION (MIND UPGRADE) ────────────────
        gemini_key = os.getenv("GEMINI_API_KEY")
        if gemini_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=gemini_key)
                model = genai.GenerativeModel("gemini-1.5-flash")
                
                # Structured prompt format to delimit and wrap untrusted data
                prompt = (
                    f"SYSTEM:\n"
                    f"You are Dobby, a smart cyber-security educational assistant for the Virex application.\n"
                    f"STRICT RULES:\n"
                    f"1. You are strictly an EDUCATIONAL guide. You may ONLY answer questions explaining threats (e.g., 'What is DDoS?'), giving general security guidance, or explaining how to use a dashboard.\n"
                    f"2. You DO NOT HAVE ACCESS to live logs, real-time stats, user data, or system internals. If the user asks for logs, amounts of attacks, top attackers, system health, or user info, you MUST politely refuse and state you only provide guidance.\n"
                    f"3. Answer in the exact language the user used (English or Egyptian Arabic), keep it natural.\n"
                    f"4. Format the response nicely using simple Markdown.\n"
                    f"5. Do NOT say you are an AI model. You are Dobby.\n\n"
                    f"USER_DATA:\n"
                    f"{user_query}"
                )
                
                response = model.generate_content(prompt)
                if response and response.text:
                    return filter_response(response.text)
            except Exception as e:
                print("Gemini API Error:", e)

        # ── FALLBACK: PURE PYTHON RULE-BASED ENGINE ──────────────
        time.sleep(0.2)
        lang     = self._lang(user_query)
        is_admin = (role == self.Role.ADMIN)
        intent   = _classify(user_query)

        # ── simple intents ───────────────────────────────────────
        if intent == "identity":       return filter_response(self._r_identity(lang))
        if intent == "greeting":       return filter_response(self._r_greeting(lang))
        if intent == "how_are_you":    return filter_response(self._r_how_are_you(lang)) # We will rewrite this function later to not leak DB stats
        if intent == "thanks":         return filter_response(self._r_thanks(lang))
        if intent == "goodbye":        return filter_response(self._r_goodbye(lang))
        if intent == "security_tips":  return filter_response(self._r_security_tips(lang))

        # ── incident_action without incident → security tips ─────
        if intent == "incident_action" and not incident_id:
            return filter_response(self._r_security_tips(lang))

        # ── incident_why without incident → clarify context ───────
        if intent == "incident_why" and not incident_id:
            if lang == 'ar':
                return "لو بتسأل عن سبب هجمة معينة، ياريت تحددها أو تفتحها من صفحة الـ Incidents عشان أقدر أحللها لك صح. 🔍"
            return "If you're asking why a specific attack happened, please provide context or open it from the Incidents page so I can analyze it for you. 🔍"
            
        # ── newly added knowledge intents ──────────────────────────
        if intent == "what_is_sqli":   return filter_response(self._r_what_is_sqli(lang))
        if intent == "what_is_xss":    return filter_response(self._r_what_is_xss(lang))
        if intent == "what_is_ddos":   return filter_response(self._r_what_is_ddos(lang))
        if intent == "what_is_malware": return filter_response(self._r_what_is_malware(lang))
        if intent == "what_is_phishing":return filter_response(self._r_what_is_phishing(lang))
        if intent == "what_is_firewall":return filter_response(self._r_what_is_firewall(lang))
        if intent == "virex_info":     return filter_response(self._r_virex_info(lang))
        if intent == "dashboard_help": return filter_response(self._r_dashboard_help(lang))

        # ── incident-specific ────────────────────────────────────
        if incident_id:
            inc = self.dashboard.incidents.get(incident_id)
            if not inc:
                return ("الحادثة دي مش موجودة في السجلات." if lang == 'ar'
                        else "This incident was not found in records.")
            if intent == "incident_why":    return filter_response(self._r_incident_why(inc, lang, is_admin))
            if intent == "incident_action": return filter_response(self._r_incident_action(inc, lang, is_admin))
            return filter_response(self._r_incident_why(inc, lang, is_admin))

        # ── unknown ──────────────────────────────────────────────
        return filter_response(self._r_unknown(lang))