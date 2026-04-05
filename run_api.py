"""
API Entry Point — Virex Security API Server
"""
import os
import logging
from dotenv import load_dotenv

load_dotenv()

# Validate config BEFORE importing Flask app (so crash is clear)
from app.config import validate_config
validate_config()

from app.api import create_api_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    logger.info("🛡️  Virex API Security System starting...")
    app = create_api_app()
    api_port = int(os.getenv("API_PORT", 5000))
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    if debug_mode:
        logger.warning("⚠️  FLASK_DEBUG=true — DO NOT use in production")

    logger.info(f"   Listening on http://0.0.0.0:{api_port}  (debug={debug_mode})")
    app.run(host="0.0.0.0", port=api_port, debug=debug_mode, use_reloader=False)
