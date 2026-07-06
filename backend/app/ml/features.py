"""
Virex Security — Security Feature Extractor v2
===============================================
يستخرج features أمنية من النص تُستخدم جنباً إلى جنب مع TF-IDF.
v2: إضافة features لـ SSTI, NoSQL, IFS bypass, obfuscation.
"""

import re
import math
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from scipy.sparse import csr_matrix


class SecurityFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Transformer متوافق مع sklearn pipeline.
    يحوّل قائمة نصوص إلى مصفوفة features أمنية رقمية (47 features).
    """

    # ── SQL ───────────────────────────────────────────────────────
    _SQL_KEYWORDS = re.compile(
        r"\b(union\s+select|insert\s+into|update\s+\w+\s+set|delete\s+from|"
        r"drop\s+table|exec\s+xp_|xp_cmdshell|information_schema|sysobjects|syscolumns|"
        r"load_file|into\s+outfile|pg_sleep|waitfor\s+delay|extractvalue|updatexml)\b",
        re.I,
    )
    _UNION_SEL   = re.compile(r"union\s+(all\s+)?select", re.I)
    _SQL_COMMENTS= re.compile(r"(--|#|/\*|\*/|;--)")
    _SQL_TAUTOLOGY = re.compile(r"(\bor\b|\band\b)\s*['\"0-9(].*?=", re.I)
    _NOSQL       = re.compile(r'(\$gt|\$lt|\$ne|\$where|\$regex|\$exists|\$in|\$nin)', re.I)

    # ── XSS ───────────────────────────────────────────────────────
    _HTML_TAGS   = re.compile(
        r"(<script|</script|<img|<iframe|<svg|<body|<input|"
        r"<form|<object|<embed|<link|<meta|<style|javascript:|"
        r"vbscript:|data:text/html)",
        re.I,
    )
    _JS_EVENTS   = re.compile(
        r"\b(onerror|onload|onclick|onmouseover|onfocus|onblur|"
        r"ontoggle|onchange|onsubmit|oninput|onkeyup|onkeydown|"
        r"onmouseout|onmouseenter|onmouseleave|ondblclick|"
        r"oncontextmenu|ondrop|ondragover)\b",
        re.I,
    )

    # ── Command Injection ─────────────────────────────────────────
    _SHELL_META      = re.compile(r"[&$|`;]")
    _SHELL_CMDS      = re.compile(
        r"\b(cat|ls|rm|wget|curl|nc|bash|sh|python|python3|perl|ruby|"
        r"php|powershell|cmd|exec|system|whoami|id|uname|ifconfig|"
        r"netstat|ping|nslookup|nmap|chmod|chown|passwd|awk|sed|sudo|"
        r"nohup|xargs|eval|find|grep|tar|zip|unzip|cp|mv|touch|mkdir|"
        r"env|printenv|export|source|echo|printf)\b",
        re.I,
    )
    _CMD_SEPARATORS  = re.compile(r"(?:;|&&|\|\||\|)")
    _SHELL_VARS      = re.compile(r"\$(?:@|\*|\$|\?|#|-|!|\{IFS\}|\{PATH\}|\{HOME\}|\{USER\})")
    _IFS_BYPASS      = re.compile(r"\$\{IFS\}|\$IFS", re.I)
    _NESTED_QUOTES   = re.compile(r"\w+['\"]\w+['\"]\w*")
    _BACKTICKS       = re.compile(r"`[^`]*`|`")
    _CMD_SUBSTITUTION= re.compile(r"\$\([^)]+\)")
    _BASE64_EXEC     = re.compile(r"(?:base64\s*-d|@b64decode|atob\()", re.I)
    _HEX_OCT_ESCAPES = re.compile(r"\\x[0-9a-fA-F]{2}|\\[0-7]{3}")
    _REPEATED_ESCAPING = re.compile(r"\\{2,}")
    _WILDCARD_CMD    = re.compile(r"/b\?n/|/bi\?/|c\[\w\]t\b", re.I)
    _NEWLINE_INJECT  = re.compile(r"%0[aA]|\\n|\\r")
    _TCP_SHELL       = re.compile(r"/dev/tcp/|/dev/udp/", re.I)

    # ── Path Traversal ────────────────────────────────────────────
    _PATH_TRAV       = re.compile(
        r"(\.\.[/\\]|%2e%2e|%252e%252e|\.\.%2f|%2e%2e%2f|"
        r"etc/passwd|etc/shadow|proc/self|windows/win\.ini|"
        r"boot\.ini|system32|\.ssh/id_rsa|\.bash_history)",
        re.I,
    )
    _PHP_WRAPPER     = re.compile(r"php://|data://|expect://|zip://|phar://", re.I)

    # ── Encoding ──────────────────────────────────────────────────
    _URL_ENC         = re.compile(r"%[0-9a-fA-F]{2}")
    _DOUBLE_ENC      = re.compile(r"%25[0-9a-fA-F]{2}")   # double URL encoding
    _HTML_ENT        = re.compile(r"&#?\w+;")
    _UNICODE_ESC     = re.compile(r"\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}")

    # ── Advanced attacks ──────────────────────────────────────────
    _JNDI     = re.compile(r"\$\{jndi:", re.I)
    _LOG4J_OBF= re.compile(r"\$\{[a-z:]+\}", re.I)          # ${lower:j} style
    _SSRF     = re.compile(
        r"(169\.254\.169\.254|metadata\.google\.internal|"
        r"127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\]|"
        r"0177\.|2130706433|192\.168\.|10\.0\.|172\.(1[6-9]|2\d|3[01])\.)",
        re.I,
    )
    _XXE      = re.compile(r"(<!DOCTYPE|<!ENTITY|SYSTEM\s+[\"']file|SYSTEM\s+[\"']http)", re.I)

    # ── SSTI — expanded ──────────────────────────────────────────
    _SSTI_JINJA  = re.compile(r"\{\{|\}\}|\{%|%\}", re.I)
    _SSTI_EL     = re.compile(r"\$\{[^}]+\}", re.I)          # EL / Freemarker / OGNL
    _SSTI_HASH   = re.compile(r"#\{[^}]+\}", re.I)           # Ruby ERB / Pebble
    _SSTI_ASP    = re.compile(r"<%=|<%\s*\w", re.I)          # ASP / Mako
    _SSTI_CLASS  = re.compile(r"__class__|__mro__|__subclasses__|__globals__|__builtins__", re.I)
    _SSTI_PROBE  = re.compile(r"\b7\*7\b|\b49\b.*\bssti\b", re.I)  # arithmetic probe

    # ── Structural ────────────────────────────────────────────────
    _SINGLE_Q = re.compile(r"'")
    _DOUBLE_Q = re.compile(r'"')

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return csr_matrix(np.array([self._features(str(t)) for t in X], dtype=np.float32))

    # ── feature vector (47 features) ─────────────────────────────
    def _features(self, text: str) -> list:
        t   = text
        low = t.lower()
        n   = max(len(t), 1)

        return [
            # ── 0-1: Length & Entropy ──
            float(n),
            self._entropy(t),

            # ── 4: Special char density ──
            len(re.findall(r"[!@#$%^&*()\[\]{};:'\"<>?/\\|`~=+\-]", t)) / n,

            # ── 5-7: SQL ──
            float(len(self._SQL_KEYWORDS.findall(low))),
            float(bool(self._UNION_SEL.search(low))),
            float(len(self._SQL_COMMENTS.findall(t))),

            # ── 8-9: SQL extras ──
            float(bool(self._SQL_TAUTOLOGY.search(low))),
            float(bool(self._NOSQL.search(t))),

            # ── 10-11: XSS ──
            float(len(self._HTML_TAGS.findall(low))),
            float(len(self._JS_EVENTS.findall(low))),

            # ── 12-21: Command injection ──
            float(len(self._SHELL_META.findall(t))),
            float(len(self._SHELL_CMDS.findall(low))),
            float(len(self._CMD_SEPARATORS.findall(t))),
            float(len(self._SHELL_VARS.findall(t))),
            float(len(self._NESTED_QUOTES.findall(t))),
            float(len(self._BACKTICKS.findall(t))),
            float(len(self._CMD_SUBSTITUTION.findall(t))),
            float(bool(self._BASE64_EXEC.search(t))),
            float(len(self._HEX_OCT_ESCAPES.findall(t))),
            float(bool(self._REPEATED_ESCAPING.search(t))),

            # ── 22-24: Command injection extras ──
            float(bool(self._IFS_BYPASS.search(t))),
            float(bool(self._WILDCARD_CMD.search(t))),
            float(bool(self._TCP_SHELL.search(t))),
            float(bool(self._NEWLINE_INJECT.search(t))),

            # ── 26-28: Path traversal ──
            float(bool(self._PATH_TRAV.search(low))),
            float(t.count("../")),
            float(t.count("..\\")),

            # ── 29: PHP wrappers ──
            float(bool(self._PHP_WRAPPER.search(low))),

            # ── 30-33: Encoding ──
            float(len(self._URL_ENC.findall(t))),
            len(self._URL_ENC.findall(t)) / n,
            float(bool(self._HTML_ENT.search(t))),
            float(bool(self._DOUBLE_ENC.search(t))),
            float(bool(self._UNICODE_ESC.search(t))),

            # ── 35-37: Advanced ──
            float(bool(self._JNDI.search(t))),
            float(bool(self._LOG4J_OBF.search(t))),
            float(bool(self._SSRF.search(low))),
            float(bool(self._XXE.search(t))),

            # ── 39-44: SSTI (expanded) ──
            float(bool(self._SSTI_JINJA.search(t))),
            float(bool(self._SSTI_EL.search(t))),
            float(bool(self._SSTI_HASH.search(t))),
            float(bool(self._SSTI_ASP.search(t))),
            float(bool(self._SSTI_CLASS.search(low))),
            float(bool(self._SSTI_PROBE.search(t))),

            # ── 45-46: Structural ──
            float(t.count("&")),
            float(t.count("?")),
            float(t.count("=")),

            # ── 48-49: Quote imbalance ──
            float(abs(len(self._SINGLE_Q.findall(t)) % 2)),
            float(abs(len(self._DOUBLE_Q.findall(t)) % 2)),

            # ── 50: Nesting depth ──
            float(max(
                self._nesting_depth(t, "(", ")"),
                self._nesting_depth(t, "{", "}"),
                self._nesting_depth(t, "[", "]"),
            )),

            # ── 51: Null byte ──
            float(bool("\x00" in t or "%00" in low)),
        ]

    @staticmethod
    def _entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(text)
        return -sum((c / n) * math.log2(c / n) for c in freq.values() if c)

    @staticmethod
    def _nesting_depth(text: str, open_ch: str, close_ch: str) -> int:
        depth = max_depth = 0
        for ch in text:
            if ch == open_ch:
                depth += 1
                max_depth = max(max_depth, depth)
            elif ch == close_ch:
                depth = max(0, depth - 1)
        return max_depth

    @property
    def feature_names(self):
        return [
            "length",
            "entropy",
            "special_char_ratio",
            "sql_keyword_count", "has_union_select", "sql_comment_count",
            "has_sql_tautology", "has_nosql_operator",
            "html_tag_count", "js_event_count",
            "shell_meta_count", "shell_cmd_count",
            "cmd_separator_count", "shell_var_count", "nested_quotes_count",
            "backticks_count", "cmd_substitution_count",
            "has_base64_exec", "hex_oct_escapes_count", "has_repeated_escaping",
            "has_ifs_bypass", "has_wildcard_cmd", "has_tcp_shell",
            "has_newline_inject",
            "has_path_traversal", "dotdot_slash_count", "dotdot_back_count",
            "has_php_wrapper",
            "url_enc_count", "url_enc_ratio", "has_html_entities",
            "has_double_encoding", "has_unicode_escape",
            "has_jndi", "has_log4j_obfuscation",
            "has_ssrf_host", "has_xxe",
            "has_ssti_jinja", "has_ssti_el", "has_ssti_hash",
            "has_ssti_asp", "has_ssti_class_access", "has_ssti_arithmetic_probe",
            "ampersand_count", "question_mark_count", "equals_count",
            "single_quote_imbalance", "double_quote_imbalance",
            "max_nesting_depth",
            "has_null_byte",
        ]
