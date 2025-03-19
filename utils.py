import json
import requests
import ipaddress
from plyer import notification  # For desktop notifications
import datetime

# Load suspicious IP patterns or addresses
with open('blocklist.json') as blocklist_file:
    blocklist = set(json.load(blocklist_file)["blocklist"])

def is_suspicious_ip(ip_address):
    """
    Checks if the given IP address is marked as suspicious.
    """
    if ip_address in blocklist:
        return True

    suspicious_patterns = ["192.168.1.", "10.10.", "172.16."]
    for pattern in suspicious_patterns:
        if ip_address.startswith(pattern):
            return True

    return False

def get_geoip_info(ip_address):
    """
    Retrieves GeoIP information for the given IP address.
    It also identifies private, multicast, and reserved IPs.
    """
    ip = ipaddress.ip_address(ip_address)

    if ip.is_private:
        return "Private IP"
    if ip.is_multicast:
        return "Multicast"
    if ip.is_unspecified or ip.is_reserved:
        return "Reserved IP"
    if ip_address == "255.255.255.255":
        return "Broadcast"

    # Primary API: ipinfo.io
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json?token=1f20023fd681f2", timeout=5)
        if response.status_code == 200:
            data = response.json()
            city = data.get('city', 'Unknown')
            region = data.get('region', 'Unknown')
            country = data.get('country', 'Unknown')
            org = data.get('org', 'Unknown ISP/Org')
            return f"{city}, {region}, {country} ({org})"
    except requests.exceptions.RequestException:
        pass  

    # Fallback API: ip-api.com
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            city = data.get('city', 'Unknown')
            region = data.get('regionName', 'Unknown')
            country = data.get('country', 'Unknown')
            isp = data.get('isp', 'Unknown ISP/Org')
            return f"{city}, {region}, {country} ({isp})"
    except requests.exceptions.RequestException:
        pass  

    return "Unknown"

def show_notification(title, message):
    """
    Displays a desktop notification for critical firewall alerts.
    """
    try:
        notification.notify(
            title=title,
            message=message,
            timeout=10
        )
    except Exception as e:
        print(f"[WARNING] Notification failed: {e}")

def log_activity(action, message):
    """
    Logs firewall activities with timestamps for record-keeping.
    """
    with open("firewall_log.txt", "a") as log_file:
        log_file.write(f"[{datetime.datetime.now()}] [{action.upper()}] {message}\n")
