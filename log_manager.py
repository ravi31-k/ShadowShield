


# import os
# from datetime import datetime

# LOG_DIR = os.path.abspath("logs")
# ALLOWED_LOG_PATH = os.path.join(LOG_DIR, "allowed")
# BLOCKED_LOG_PATH = os.path.join(LOG_DIR, "blocked")
# ALERT_LOG_PATH = os.path.join(LOG_DIR, "alert")

# os.makedirs(ALLOWED_LOG_PATH, exist_ok=True)
# os.makedirs(BLOCKED_LOG_PATH, exist_ok=True)
# os.makedirs(ALERT_LOG_PATH, exist_ok=True)

# def write_log(log_type, message):
#     log_paths = {
#         "allowed": ALLOWED_LOG_PATH,
#         "blocked": BLOCKED_LOG_PATH,
#         "alert": ALERT_LOG_PATH
#     }

#     log_path = os.path.join(log_paths.get(log_type, ALERT_LOG_PATH), f"{log_type}.log")
#     with open(log_path, "a") as log_file:
#         log_file.write(f"{datetime.now()} - {message}\n")

import os
import json
import requests
from datetime import datetime

# Splunk Configuration
SPLUNK_URL = "http://localhost:8000/services/collector"  # Change if using a remote Splunk instance
SPLUNK_TOKEN = "c17d5964-7a32-4fd8-9577-f5461dabfc7d"  # Use your Splunk HEC token

# Local Logging Setup
LOG_DIR = os.path.abspath("logs")
ALLOWED_LOG_PATH = os.path.join(LOG_DIR, "allowed")
BLOCKED_LOG_PATH = os.path.join(LOG_DIR, "blocked")
ALERT_LOG_PATH = os.path.join(LOG_DIR, "alert")

# Ensure Directories Exist
os.makedirs(ALLOWED_LOG_PATH, exist_ok=True)
os.makedirs(BLOCKED_LOG_PATH, exist_ok=True)
os.makedirs(ALERT_LOG_PATH, exist_ok=True)

# Function to Send Logs to Splunk
def send_to_splunk(event_type, message):
    log_entry = {
        "time": datetime.utcnow().isoformat(),
        "event": {
            "type": event_type,
            "message": message,
            "firewall": "Shatachandra Wall"
        }
    }

    headers = {
        "Authorization": f"Splunk {SPLUNK_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(SPLUNK_URL, headers=headers, json={"event": log_entry})
        if response.status_code == 200:
            print(f"[INFO] Log sent to Splunk: {event_type} - {message}")
        else:
            print(f"[ERROR] Splunk Log Failed: {response.text}")
    except Exception as e:
        print(f"[ERROR] Failed to send log to Splunk: {e}")

# Function to Write Logs Locally
def write_log(log_type, message):
    log_paths = {
        "allowed": ALLOWED_LOG_PATH,
        "blocked": BLOCKED_LOG_PATH,
        "alert": ALERT_LOG_PATH
    }

    log_path = os.path.join(log_paths.get(log_type, ALERT_LOG_PATH), f"{log_type}.log")
    
    with open(log_path, "a") as log_file:
        log_file.write(f"{datetime.now()} - {message}\n")

    # Also send logs to Splunk for central monitoring
    send_to_splunk(log_type, message)

# Example Usage
if __name__ == "__main__":
    write_log("alert", "Suspicious connection detected from 203.0.113.45 (China)")
    write_log("blocked", "Blocked unauthorized SSH attempt from 192.168.1.200")
    write_log("allowed", "Allowed HTTPS connection to 8.8.8.8")
