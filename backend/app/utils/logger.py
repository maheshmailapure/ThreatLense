import logging
import os
import sys
from datetime import datetime

LOG_DIR = os.getenv("LOG_DIR", "./logs")
os.makedirs(LOG_DIR, exist_ok=True)

log_filename = os.path.join(LOG_DIR, f"ai_ids_{datetime.now().strftime('%Y%m%d')}.log")

# Configure root logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_filename, encoding="utf-8")
    ]
)

logger = logging.getLogger("ThreatLense")

def log_event(event_type: str, details: dict):
    """Log structured security and operational events."""
    try:
        logger.info(f"EVENT={event_type} | {details}")
    except Exception:
        pass
