import json
import psutil
import requests
import time
from collections import defaultdict
from plyer import notification
from scapy.all import sniff, IP, TCP, UDP, get_if_list

# Load Firewall Rules from JSON File
def load_rules():
    with open("rules.json", "r") as file:
        return json.load(file)

rules = load_rules()

# Identify Active Interface Dynamically
def detect_interface():
    for iface in get_if_list():
        if "wifi" in iface.lower() or "NPF" in iface:
            return iface
    return None

# Desktop Notification Function
def show_notification(title, message):
    notification.notify(
        title=title,
        message=message,
        app_name="Firewall Alert",
        timeout=10
    )

# GeoIP Lookup Function with Retry Logic
def get_geoip_info(ip_address):
    API_URL = f"https://ipinfo.io/{ip_address}/json?token=1f20023fd681f2"
    
    for attempt in range(3):
        try:
            response = requests.get(API_URL, timeout=5)
            response.raise_for_status()
            data = response.json()

            location = f"{data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}, {data.get('country', 'Unknown')} ({data.get('org', 'Unknown ISP/Organization')})"
            return location
        except requests.exceptions.RequestException:
            return "[ERROR] Failed to fetch GeoIP info"

# Packet Filtering Logic
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"

        print(f"[ALLOWED] {ip_src} → {ip_dst} | Protocol: {protocol}")

# Start Sniffing
def start_sniffing():
    selected_interface = detect_interface()
    if selected_interface:
        print(f"[INFO] Starting packet sniffing on interface: {selected_interface}")
        sniff(iface=selected_interface, prn=packet_callback, store=0)
    else:
        print("[ERROR] Could not detect a valid network interface.")

if __name__ == "__main__":
    start_sniffing()
