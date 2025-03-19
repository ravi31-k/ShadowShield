import os
import shutil
from datetime import datetime, timedelta

LOG_DIR = os.path.abspath("logs")
ALLOWED_LOG_PATH = os.path.join(LOG_DIR, "allowed")
BLOCKED_LOG_PATH = os.path.join(LOG_DIR, "blocked")
INTRUSION_LOG_PATH = os.path.join(LOG_DIR, "intrusion")

os.makedirs(ALLOWED_LOG_PATH, exist_ok=True)
os.makedirs(BLOCKED_LOG_PATH, exist_ok=True)
os.makedirs(INTRUSION_LOG_PATH, exist_ok=True)

MAX_LOG_SIZE = 5 * 1024 * 1024
LOG_RETENTION_DAYS = 7

def rotate_logs(log_type):
    log_path = (
        ALLOWED_LOG_PATH if log_type == "allowed"
        else BLOCKED_LOG_PATH if log_type == "blocked"
        else INTRUSION_LOG_PATH
    )

    current_log = os.path.join(log_path, f"{log_type}.log")

    if os.path.exists(current_log) and os.path.getsize(current_log) >= MAX_LOG_SIZE:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        archive_name = os.path.join(log_path, f"{log_type}_{timestamp}.log")
        shutil.move(current_log, archive_name)
        print(f"[INFO] Log rotated: {archive_name}")

def write_log(log_type, message):
    log_paths = {
        "allowed": ALLOWED_LOG_PATH,
        "blocked": BLOCKED_LOG_PATH,
        "intrusion": INTRUSION_LOG_PATH
    }

    log_path = os.path.join(log_paths.get(log_type, INTRUSION_LOG_PATH), f"{log_type}.log")

    rotate_logs(log_type)
    with open(log_path, "a") as log_file:
        log_file.write(f"{datetime.now()} - {message}\n")
