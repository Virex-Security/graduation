"""
Virex Security — Security Feature Extractor
=============================================
يستخرج features أمنية من النص تُستخدم جنباً إلى جنب مع TF-IDF
"""

import re
import math
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from scipy.sparse import csr_matrix


class SecurityFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Transformer متوافق مع sklearn pipeline.
    يحوّل قائمة نصوص إلى مصفوفة features أمنية رقمية.
    """

    # SQL keywords
    _SQL_KEYWORDS = re.compile(
        r"\b(select|insert|update|delete|drop|union|exec|execute|"
        r"sleep|benchmark|waitfor|having|group\s+by|order\s+by|"
        r"information_schema|sysobjects|syscolumns|xp_cmdshell|"
        r"load_file|into\s+outfile|pg_sleep|convert|cast)\b",
        re.I,
    )

    # HTML/JS dangerous patterns
    _HTML_TAGS = re.compile(
        r"(<script|</script|<img|<iframe|<svg|<body|<input|"
        r"<form|<object|<embed|<link|<meta|<style|javascript:|"
        r"vbscript:|data:text/html)",
        re.I,
    )
    _JS_EVENTS = re.compile(
        r"\b(onerror|onload|onclick|onmouseover|onfocus|onblur|"
        r"ontoggle|onchange|onsubmit|oninput|onkeyup|onkeydown)\b",
        re.I,
    )

    # Shell metacharacters
    _SHELL_META = re.compile(r"[;|`&$]|\$\(|\|\|")

    # Shell commands
    _SHELL_CMDS = re.compile(
        r"\b(cat|ls|rm|wget|curl|nc|bash|sh|python|perl|ruby|"
        r"php|powershell|cmd|exec|system|whoami|id|uname|ifconfig|"
        r"netstat|ping|nslookup|nmap|chmod|chown|passwd)\b",
        re.I,
    )

    # Path traversal
    _PATH_TRAV = re.compile(
        r"(\.\.[\\/]|%2e%2e|%252e%252e|\.\.%2f|%2e%2e%2f|"
        r"etc/passwd|etc/shadow|proc/self|windows/win\.ini)",
        re.I,
    )

    # URL encoding
    _URL_ENC = re.compile(r"%[0-9a-fA-F]{2}")

    # HTML entities
    _HTML_ENT = re.compile(r"&#?\w+;")

    # SQL comment sequences
    _SQL_COMMENTS = re.compile(r"(--|#|/\*|\*/|;--)")

    # UNION SELECT
    _UNION_SEL = re.compile(r"union\s+(all\s+)?select", re.I)

    # JNDI / Log4Shell
    _JNDI = re.compile(r"\$\{jndi:", re.I)

    # SSRF patterns
    _SSRF = re.compile(
        r"(169\.254\.169\.254|metadata\.google\.internal|"
        r"127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])",
        re.I,
    )

    # XXE patterns
    _XXE = re.compile(r"(<!DOCTYPE|<!ENTITY|SYSTEM\s+[\"']file|SYSTEM\s+[\"']http)", re.I)

    # SSTI patterns
    _SSTI = re.compile(r"(\{\{|\}\}|\$\{|#\{|<%=|%>)", re.I)

    # Quote imbalance helper
    _SINGLE_Q = re.compile(r"'")
    _DOUBLE_Q = re.compile(r'"')

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return csr_matrix(np.array([self._features(str(t)) for t in X], dtype=np.float32))

    # ── feature vector ────────────────────────────────────────
    def _features(self, text: str) -> list:
        t   = text
        low = t.lower()
        n   = max(len(t), 1)

        return [
            # length
            float(n),
            float(min(n / 500.0, 1.0)),

            # entropy
            self._entropy(t),
            self._entropy(t) / math.log2(max(n, 2)),

            # special-char density
            len(re.findall(r"[!@#$%^&*()\[\]{};:'\",<>?/\\|`~=+\-]", t)) / n,

            # sql
            float(len(self._SQL_KEYWORDS.findall(low))),
            float(bool(self._UNION_SEL.search(low))),
            float(len(self._SQL_COMMENTS.findall(t))),

            # xss
            float(len(self._HTML_TAGS.findall(low))),
            float(len(self._JS_EVENTS.findall(low))),

            # command injection
            float(len(self._SHELL_META.findall(t))),
            float(len(self._SHELL_CMDS.findall(low))),

            # path traversal
            float(bool(self._PATH_TRAV.search(low))),
            float(t.count("../")),
            float(t.count("..\\")),

            # encoding
            float(len(self._URL_ENC.findall(t))),
            len(self._URL_ENC.findall(t)) / n,
            float(bool(self._HTML_ENT.search(t))),

            # advanced attacks
            float(bool(self._JNDI.search(t))),
            float(bool(self._SSRF.search(low))),
            float(bool(self._XXE.search(t))),
            float(bool(self._SSTI.search(t))),

            # structural
            float(t.count("&")),
            float(t.count("?")),
            float(t.count("=")),

            # quote imbalance
            float(abs(len(self._SINGLE_Q.findall(t)) % 2)),
            float(abs(len(self._DOUBLE_Q.findall(t)) % 2)),

            # nesting depth
            float(max(self._nesting_depth(t, "(", ")"),
                       self._nesting_depth(t, "{", "}"),
                       self._nesting_depth(t, "[", "]"))),

            # null byte
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
            "length", "length_norm",
            "entropy", "entropy_norm",
            "special_char_ratio",
            "sql_keyword_count", "has_union_select", "sql_comment_count",
            "html_tag_count", "js_event_count",
            "shell_meta_count", "shell_cmd_count",
            "has_path_traversal", "dotdot_slash_count", "dotdot_back_count",
            "url_enc_count", "url_enc_ratio", "has_html_entities",
            "has_jndi", "has_ssrf_host", "has_xxe", "has_ssti",
            "ampersand_count", "question_mark_count", "equals_count",
            "single_quote_imbalance", "double_quote_imbalance",
            "max_nesting_depth",
            "has_null_byte",
        ]
