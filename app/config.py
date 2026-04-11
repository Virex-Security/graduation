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
    "REDIS_URL":             "redis://localhost:6379",
}


# ── Insecure default values that must be changed in production ──
_INSECURE_VALUES = {
    "SECRET_KEY": [
        "change-me-generate-with-secrets-token-hex-32",
        "change-me-in-production",
        "fallback-dev-key-change-in-production",
        "dev-secret",
    ]
}


def validate_config(strict: bool = False) -> bool:
    """
    Validate environment configuration.
    Raises SystemExit(1) if mandatory security requirements are not met.
    """
    errors = []
    warnings = []

    # 1. Enforce Mandatory SECRET_KEY
    secret = os.getenv("SECRET_KEY", "").strip()
    if not secret:
        errors.append("  ❌ SECRET_KEY is not set")
    else:
        # Enforce Minimum Length (Mandatory)
        if len(secret) < 32:
            errors.append(f"  ❌ SECRET_KEY is too short ({len(secret)} chars, minimum 32)")
        
        # Enforce No Insecure Defaults (Mandatory)
        if secret in _INSECURE_VALUES.get("SECRET_KEY", []):
            errors.append(f"  ❌ SECRET_KEY is using a known insecure default value")

    # 2. Check other required variables
    for key in _REQUIRED:
        if key == "SECRET_KEY": continue # Already checked Above
        val = os.getenv(key, "").strip()
        if not val:
            errors.append(f"  ❌ {key} is not set")

    # 3. Warnings for non-critical config
    if not os.getenv("SMTP_EMAIL") or not os.getenv("SMTP_PASSWORD"):
        warnings.append("  ⚠️  SMTP_EMAIL / SMTP_PASSWORD not set — password reset will not work")

    if not cookie_secure():
        warnings.append("  ⚠️  COOKIE_SECURE is disabled — auth cookies will be sent over HTTP")

    # Report results
    if warnings:
        logger.warning("[CONFIG] Configuration warnings:")
        for w in warnings:
            logger.warning(w)

    if errors:
        logger.error("[CONFIG] ❌ FATAL: Configuration requirements not met — cannot start:")
        for e in errors:
            logger.error(e)
        logger.error("[CONFIG] Ensure SECRET_KEY is at least 32 random characters.")
        sys.exit(1)

    logger.info("[CONFIG] ✅ Configuration successfully validated")
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


def redis_url() -> str:
    return os.getenv("REDIS_URL", _DEFAULTS.get("REDIS_URL", ""))

