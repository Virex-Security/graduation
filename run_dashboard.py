"""
Dashboard Entry Point — Virex SIEM Dashboard
"""
import os
import logging
from dotenv import load_dotenv

load_dotenv()

from app.config import validate_config
<<<<<<< HEAD
validate_config()
=======

is_prod = os.getenv("FLASK_ENV", "development") == "production"
validate_config(strict=is_prod)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

from app.dashboard import create_dashboard_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

<<<<<<< HEAD
if __name__ == '__main__':
    logger.info("📊 Virex SIEM Dashboard starting...")
    app = create_dashboard_app()
=======
app = create_dashboard_app()

if __name__ == '__main__':
    logger.info("📊 Virex SIEM Dashboard starting...")

>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
    dashboard_port = int(os.getenv("DASHBOARD_PORT", 8070))
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    if debug_mode:
        logger.warning("⚠️  FLASK_DEBUG=true — DO NOT use in production")

    logger.info(f"   Listening on http://0.0.0.0:{dashboard_port}  (debug={debug_mode})")
    app.run(host="0.0.0.0", port=dashboard_port, debug=debug_mode, use_reloader=False)
