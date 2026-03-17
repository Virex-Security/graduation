"""
API Entry Point - Start the security API server
"""
import os
import logging
from dotenv import load_dotenv
from app.api import create_api_app

load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if __name__ == '__main__':
    print("🛡️ API Security System with ML Started")
    app = create_api_app()
    api_port = int(os.getenv("API_PORT", 5000))
    app.run(host="0.0.0.0", port=api_port, debug=True)
