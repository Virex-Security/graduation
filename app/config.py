"""
Virex Security — Centralized Configuration & Startup Validator
==============================================================
All configuration comes from environment variables (loaded via .env).
Call validate_config() before starting any Flask app.
"""
import os
import sys
import logging

logger = logging.getLogger(__name__)

# ── Required variables (app will refuse to start without these) ──
_REQUIRED = [
    "SECRET_KEY",
    "INTERNAL_API_SECRET",
]

# ── Variables that have safe defaults ──
_DEFAULTS = {
    "API_PORT":              "5000",
    "DASHBOARD_PORT":        "8070",
    "COOKIE_SECURE":         "true",
    "FLASK_DEBUG":           "false",
    "ALLOWED_ORIGINS":       "http://127.0.0.1:3000,http://localhost:3000",
    "DASHBOARD_URL":         "http://127.0.0.1:8070",
    "DASHBOARD_API_ENABLED": "true",
    "MAX_CONTENT_LENGTH":    "1048576",
    "SMTP_EMAIL":            "",
    "SMTP_PASSWORD":         "",
}

# ── Insecure default values that must be changed in production ──
_INSECURE_VALUES = {
    "SECRET_KEY": [
        "change-me-generate-with-secrets-token-hex-32",
        "change-me-in-production",
        "fallback-dev-key-change-in-production",
        "dev-secret",
        "dev-secret-key",
        "secret",
        "password",
        "test-secret-key-for-ci-minimum-32-chars!!",
    ],
    "INTERNAL_API_SECRET": [
        "supersecrettoken",
        "secret",
        "changeme",
        "internal-secret",
        "test-internal-secret-for-ci-only-32chars",
        "password",
        "admin",
    ],
}


def validate_config(strict: bool = False) -> bool:
    """
    Validate environment configuration.

    Args:
        strict: If True, also reject insecure default values
                (use this for production deployments).

    Returns:
        True if valid. Logs errors and raises SystemExit if not.
    """
    errors = []
    warnings = []

    # Check required vars
    for key in _REQUIRED:
        val = os.getenv(key, "").strip()
        if not val:
            errors.append(f"  ❌ {key} is not set")
        elif strict and key in _INSECURE_VALUES:
            if val in _INSECURE_VALUES[key]:
                errors.append(f"  ❌ {key} is still using an insecure default value")

    # Check insecure values in non-strict mode (warn only)
    if not strict:
        for key, bad_values in _INSECURE_VALUES.items():
            val = os.getenv(key, "").strip()
            if val in bad_values:
                warnings.append(f"  ⚠️  {key} is using an insecure default — change before production")

    # Check SMTP config (warn if missing — not required to start)
    if not os.getenv("SMTP_EMAIL") or not os.getenv("SMTP_PASSWORD"):
        warnings.append("  ⚠️  SMTP_EMAIL / SMTP_PASSWORD not set — password reset will not work")

    if not cookie_secure():
        warnings.append("  ⚠️  COOKIE_SECURE is disabled — auth cookies will be sent over HTTP (insecure in production)")

    # Check SECRET_KEY minimum length and entropy
    secret = os.getenv("SECRET_KEY", "")
    if secret and len(secret) < 64:
        errors.append(f"  ❌ SECRET_KEY is too short ({len(secret)} chars, minimum 64)")
    # Detect sequential/low-entropy patterns like a1b2c3d4...
    if secret and len(secret) >= 8:
        unique_chars = len(set(secret))
        if unique_chars < 16:
            errors.append("  ❌ SECRET_KEY appears low-entropy (too few unique characters) — regenerate with secrets.token_hex(64)")

    # Check INTERNAL_API_SECRET minimum length
    internal = os.getenv("INTERNAL_API_SECRET", "")
    if internal and len(internal) < 32:
        errors.append(f"  ❌ INTERNAL_API_SECRET is too short ({len(internal)} chars, minimum 32)")

    # Report
    if warnings:
        logger.warning("[CONFIG] Configuration warnings:")
        for w in warnings:
            logger.warning(w)

    if errors:
        logger.error("[CONFIG] ❌ Configuration errors — cannot start:")
        for e in errors:
            logger.error(e)
        logger.error("[CONFIG] Copy .env.example to .env and fill in all required values.")
        sys.exit(1)

    logger.info("[CONFIG] ✅ Configuration validated")
    return True


def get(key: str) -> str:
    """Get config value, returning the default if not set."""
    return os.getenv(key, _DEFAULTS.get(key, ""))


def get_bool(key: str) -> bool:
    return get(key).lower() in ("1", "true", "yes", "on")


def get_int(key: str) -> int:
    try:
        return int(get(key))
    except ValueError:
        return int(_DEFAULTS.get(key, "0"))


def cookie_secure() -> bool:
    return get_bool("COOKIE_SECURE")


def flask_debug() -> bool:
    return get_bool("FLASK_DEBUG")


def secret_key() -> str:
    return os.environ.get("SECRET_KEY", "")


def internal_secret() -> str:
    return os.environ.get("INTERNAL_API_SECRET", "")


def smtp_email() -> str:
    return os.getenv("SMTP_EMAIL", "")


def smtp_password() -> str:
    return os.getenv("SMTP_PASSWORD", "")
