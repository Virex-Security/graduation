"""
API Entry Point — Virex Security API Server
"""
import os
import logging
from dotenv import load_dotenv

load_dotenv()

# Validate config BEFORE importing Flask app (so crash is clear)
from app.config import validate_config
<<<<<<< HEAD
validate_config()
=======
<<<<<<< HEAD
validate_config()
=======

is_prod = os.getenv("FLASK_ENV", "development") == "production"
validate_config(strict=is_prod)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578

from app.api import create_api_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

<<<<<<< HEAD
if __name__ == '__main__':
    logger.info("🛡️  Virex API Security System starting...")
    app = create_api_app()
=======
<<<<<<< HEAD
if __name__ == '__main__':
    logger.info("🛡️  Virex API Security System starting...")
    app = create_api_app()
=======
app = create_api_app()

if __name__ == '__main__':
    logger.info("🛡️  Virex API Security System starting...")

>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    api_port = int(os.getenv("API_PORT", 5000))
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    if debug_mode:
        logger.warning("⚠️  FLASK_DEBUG=true — DO NOT use in production")

    logger.info(f"   Listening on http://0.0.0.0:{api_port}  (debug={debug_mode})")
    app.run(host="0.0.0.0", port=api_port, debug=debug_mode, use_reloader=False)
