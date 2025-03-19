# {
#     "block_ips": ["192.168.1.200", "203.0.113.45"],
#     "allow_ports": [22, 80, 443],
#     "block_ports": [23, 3389],
#     "protocols": ["TCP", "UDP"]
# }
# import os
# import shutil
# from datetime import datetime, timedelta

# LOG_DIR = os.path.abspath("logs")
# ALLOWED_LOG_PATH = os.path.join(LOG_DIR, "allowed")
# BLOCKED_LOG_PATH = os.path.join(LOG_DIR, "blocked")
# INTRUSION_LOG_PATH = os.path.join(LOG_DIR, "intrusion")

# os.makedirs(ALLOWED_LOG_PATH, exist_ok=True)
# os.makedirs(BLOCKED_LOG_PATH, exist_ok=True)
# os.makedirs(INTRUSION_LOG_PATH, exist_ok=True)

# MAX_LOG_SIZE = 5 * 1024 * 1024
# LOG_RETENTION_DAYS = 7

# def rotate_logs(log_type):
#     log_path = (
#         ALLOWED_LOG_PATH if log_type == "allowed"
#         else BLOCKED_LOG_PATH if log_type == "blocked"
#         else INTRUSION_LOG_PATH
#     )

#     current_log = os.path.join(log_path, f"{log_type}.log")

#     if os.path.exists(current_log) and os.path.getsize(current_log) >= MAX_LOG_SIZE:
#         timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
#         archive_name = os.path.join(log_path, f"{log_type}_{timestamp}.log")
#         shutil.move(current_log, archive_name)
#         print(f"[INFO] Log rotated: {archive_name}")

# def write_log(log_type, message):
#     log_paths = {
#         "allowed": ALLOWED_LOG_PATH,
#         "blocked": BLOCKED_LOG_PATH,
#         "intrusion": INTRUSION_LOG_PATH
#     }

#     log_path = os.path.join(log_paths.get(log_type, INTRUSION_LOG_PATH), f"{log_type}.log")

#     rotate_logs(log_type)
#     with open(log_path, "a") as log_file:
#         log_file.write(f"{datetime.now()} - {message}\n")


import os
import shutil
import json
from datetime import datetime, timedelta

# Load Configuration
with open('rules.json') as config_file:
    config = json.load(config_file)

# Log Directory Configuration
LOG_DIR = os.path.abspath(config['log_settings']['log_directory'])
ALLOWED_LOG_PATH = os.path.join(LOG_DIR, "allowed")
BLOCKED_LOG_PATH = os.path.join(LOG_DIR, "blocked")
INTRUSION_LOG_PATH = os.path.join(LOG_DIR, "intrusion")

# Ensure Log Directories Exist
os.makedirs(ALLOWED_LOG_PATH, exist_ok=True)
os.makedirs(BLOCKED_LOG_PATH, exist_ok=True)
os.makedirs(INTRUSION_LOG_PATH, exist_ok=True)

# Log Management Parameters
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5 MB
LOG_RETENTION_DAYS = 7
LOG_FORMAT = config['log_settings']['log_format']

# Log Rotation
def rotate_logs(log_type):
    log_path = {
        "allowed": ALLOWED_LOG_PATH,
        "blocked": BLOCKED_LOG_PATH,
        "intrusion": INTRUSION_LOG_PATH
    }.get(log_type, INTRUSION_LOG_PATH)

    current_log = os.path.join(log_path, f"{log_type}.log")

    if os.path.exists(current_log) and os.path.getsize(current_log) >= MAX_LOG_SIZE:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        archive_name = os.path.join(log_path, f"{log_type}_{timestamp}.log")
        shutil.move(current_log, archive_name)
        print(f"[INFO] Log rotated: {archive_name}")

# Log Writing Function
def write_log(log_type, message):
    log_paths = {
        "allowed": ALLOWED_LOG_PATH,
        "blocked": BLOCKED_LOG_PATH,
        "intrusion": INTRUSION_LOG_PATH
    }

    log_path = os.path.join(log_paths.get(log_type, INTRUSION_LOG_PATH), f"{log_type}.log")

    rotate_logs(log_type)
    with open(log_path, "a") as log_file:
        timestamp = datetime.now().strftime(LOG_FORMAT)
        log_file.write(f"[{timestamp}] {message}\n")

# Old Log Cleanup
def cleanup_old_logs():
    for log_folder in [ALLOWED_LOG_PATH, BLOCKED_LOG_PATH, INTRUSION_LOG_PATH]:
        for log_file in os.listdir(log_folder):
            log_file_path = os.path.join(log_folder, log_file)
            file_time = datetime.fromtimestamp(os.path.getctime(log_file_path))
            if datetime.now() - file_time > timedelta(days=LOG_RETENTION_DAYS):
                os.remove(log_file_path)
                print(f"[INFO] Deleted old log file: {log_file}")

# Usage Examples
# write_log("allowed", "192.168.1.5 --> 8.8.8.8 | Protocol: TCP")
# write_log("alert", "Suspicious connection detected from 202.54.1.2 (China)")
# cleanup_old_logs()
