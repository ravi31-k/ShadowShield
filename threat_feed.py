import requests
import json
import time
from log_manager import write_log  # Ensure this module exists for logging

# -----------------------------
# Threat Feed Configuration
# -----------------------------
THREAT_FEED_SOURCES = [
    "https://api.abuseipdb.com/dcdcf09a90b8d1630358693c7b51d38824629f1f2d780feaf82a1a2def2567bfcced4febb8618e0f/v2/blacklist",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",  
    "https://urlhaus-api.abuse.ch/v1/urls/recent/",  
    "https://iplists.firehol.org/files/firehol_level1.netset"
]

# Cache file for offline support
CACHE_FILE = "threat_cache.json"
CACHE_EXPIRY = 6 * 3600  # 6 hours in seconds

# -----------------------------
# Load Cached Data (Offline Support)
# -----------------------------
def load_cached_data():
    try:
        with open(CACHE_FILE, 'r') as file:
            cache = json.load(file)
            if time.time() - cache['timestamp'] < CACHE_EXPIRY:
                print("[INFO] Loaded cached threat data.")
                return cache['malicious_ips'], cache['blocked_ports'], cache['malicious_domains']
            else:
                print("[INFO] Cache expired. Fetching fresh data.")
                return [], [], []
    except (FileNotFoundError, KeyError, json.JSONDecodeError):
        print("[INFO] No valid cache found.")
        return [], [], []

# -----------------------------
# Save Data to Cache
# -----------------------------
def save_to_cache(malicious_ips, blocked_ports, malicious_domains):
    cache_data = {
        "timestamp": time.time(),
        "malicious_ips": malicious_ips,
        "blocked_ports": blocked_ports,
        "malicious_domains": malicious_domains
    }
    with open(CACHE_FILE, 'w') as file:
        json.dump(cache_data, file)

# -----------------------------
# Fetch Latest Threat Data
# -----------------------------
def fetch_threat_data():
    malicious_ips, blocked_ports, malicious_domains = set(), set(), set()

    for url in THREAT_FEED_SOURCES:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            malicious_ips.update(data.get("malicious_ips", []))
            blocked_ports.update(data.get("blocked_ports", []))
            malicious_domains.update(data.get("malicious_domains", []))

            print(f"[INFO] Fetched threat data from {url}")
        except requests.exceptions.RequestException:
            print(f"[WARNING] Failed to fetch data from {url}")
            write_log("warning", f"Failed to fetch data from {url}")

    # Cache the fetched data
    if malicious_ips or blocked_ports or malicious_domains:
        save_to_cache(malicious_ips, blocked_ports, malicious_domains)

    return malicious_ips, blocked_ports, malicious_domains

# -----------------------------
# Threat Checking Logic
# -----------------------------
malicious_ips, blocked_ports, malicious_domains = load_cached_data()

def is_ip_threat(ip):
    return ip in malicious_ips

def is_port_threat(port):
    return str(port) in blocked_ports

def is_domain_threat(domain):
    return domain in malicious_domains
