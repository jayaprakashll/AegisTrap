
import json
import os
import logging
from datetime import datetime
from config import config

log_dir = config['logging']['log_directory']
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, f"log_{datetime.now().strftime('%Y-%m-%d')}.json")

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_detection(detection_data):
    try:
        with open(log_file, "a") as f:
            json.dump(detection_data, f)
            f.write("\n")
        logging.info(f"Logged detection: {detection_data}")
    except Exception as e:
        logging.error(f"Failed to log detection: {e}")

def read_logs():
    try:
        with open(log_file, "r") as f:
            return f.readlines()
    except FileNotFoundError:
        logging.warning("Log file not found.")
        return []

def clear_logs():
    try:
        open(log_file, "w").close()
        logging.info("Log file cleared.")
    except Exception as e:
        logging.error(f"Failed to clear logs: {e}")
