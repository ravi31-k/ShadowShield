import json
import psutil
import subprocess
import time
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, get_if_list, get_if_hwaddr
from utils import get_geoip_info, show_notification, log_activity, is_suspicious_ip
from dpi_engine import dpi_packet_callback  # DPI Engine Integration

# -----------------------------
# Load Configuration Files
# -----------------------------
with open('firewall_rules.json') as rules_file:
    firewall_rules = json.load(rules_file)["rules"]

with open('blocklist.json') as blocklist_file:
    blocklist = set(json.load(blocklist_file)["blocklist"])

# -----------------------------
# Detect Interface with MAC Matching
# -----------------------------
def get_interface_guid():
    active_interface = None
    wifi_mac = None

    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                if "Wi-Fi" in interface or "Ethernet" in interface:
                    active_interface = interface
                    wifi_mac = addr.address.replace(":", "-").lower()
                    break

    if not active_interface or not wifi_mac:
        print("[ERROR] No active Wi-Fi/Ethernet interface detected.")
        return None

    print(f"[INFO] Active Interface Detected (psutil): {active_interface} | MAC: {wifi_mac}")

    for iface in get_if_list():
        try:
            scapy_mac = get_if_hwaddr(iface).replace(":", "-").lower()
            if scapy_mac == wifi_mac:
                print(f"[INFO] Matched Interface Found: {iface}")
                return iface
        except Exception:
            continue

    print("[WARNING] Automatic detection failed. Showing available interfaces:")
    for idx, iface in enumerate(get_if_list(), start=1):
        print(f"{idx}. {iface}")

    choice = input("[INPUT] Select the correct interface (Enter the number): ")
    try:
        return get_if_list()[int(choice) - 1]
    except (IndexError, ValueError):
        print("[ERROR] Invalid selection.")
        return None

# -----------------------------
# Restart Npcap Service
# -----------------------------
def restart_npcap():
    try:
        subprocess.run(['sc', 'stop', 'npcap'], check=True)
        time.sleep(5)
        subprocess.run(['sc', 'start', 'npcap'], check=True)
        time.sleep(5)
        print("[INFO] Npcap service restarted successfully.")
    except subprocess.CalledProcessError:
        print("[WARNING] Npcap restart failed. Please restart manually if required.")

# -----------------------------
# Packet Filtering Logic (Updated with DPI Integration)
# -----------------------------
def packet_callback(packet):
    if not packet.haslayer(IP):
        return  # Ignore non-IP packets

    if packet.haslayer(Raw) and not packet[Raw].load:
        return  # Ignore empty packets

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else "N/A"
    dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else "N/A"

    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"

    # GeoIP Location Information
    src_location = get_geoip_info(ip_src)
    dst_location = get_geoip_info(ip_dst)

    # DPI Integration - Deep Packet Inspection for Malicious Patterns
    is_suspicious, details = dpi_packet_callback(packet)
    if is_suspicious:
        alert_message = (f"[ALERT] Suspicious Packet: {ip_src}:{src_port} --> {ip_dst}:{dst_port} | "
                         f"Protocol: {protocol} | Location: {src_location} -> {dst_location} | Details: {details}")
        print(alert_message)
        show_notification("Firewall Alert", alert_message)
        log_activity("alert", alert_message)
        return  

    # Blocklist Checking
    if ip_src in blocklist or ip_dst in blocklist:
        blocked_message = (f"[BLOCKED] {ip_src}:{src_port} --> {ip_dst}:{dst_port} | "
                           f"Protocol: {protocol} | Location: {src_location} -> {dst_location} (Blocklist Match)")
        print(blocked_message)
        log_activity("blocked", blocked_message)
        return  

    # Firewall Rules Processing
    for rule in firewall_rules:
        conditions = rule["conditions"]

        if "ip" in conditions and (ip_src in conditions["ip"] or ip_dst in conditions["ip"]):
            if rule["action"] == "block":
                blocked_message = (f"[BLOCKED] {ip_src}:{src_port} --> {ip_dst}:{dst_port} | "
                                   f"Rule: {rule['rule_name']} | Location: {src_location} -> {dst_location}")
                print(blocked_message)
                log_activity("blocked", blocked_message)
                return
            elif rule["action"] == "alert":
                alert_message = (f"[ALERT] {ip_src}:{src_port} --> {ip_dst}:{dst_port} | "
                                 f"Rule: {rule['rule_name']} | Location: {src_location} -> {dst_location}")
                print(alert_message)
                log_activity("alert", alert_message)

    # Allow Remaining Traffic
    allowed_message = (f"[ALLOWED] {ip_src}:{src_port} --> {ip_dst}:{dst_port} | "
                       f"Protocol: {protocol} | Location: {src_location} -> {dst_location}")
    print(allowed_message)
    log_activity("allowed", allowed_message)

# -----------------------------
# Start Sniffing
# -----------------------------
def start_sniffing():
    selected_interface = get_interface_guid()
    if selected_interface:
        print(f"[INFO] Starting packet sniffing on interface: {selected_interface}")
        sniff(iface=selected_interface, prn=packet_callback, store=0)
    else:
        print("[ERROR] Could not detect the correct interface.")

# -----------------------------
# Main Execution
# -----------------------------
if __name__ == "__main__":
    restart_npcap()
    start_sniffing()

# import json
# import psutil
# import requests
# import subprocess
# import ipaddress 
# import time
# from collections import defaultdict
# from plyer import notification
# from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, get_if_list, get_if_hwaddr
# from log_manager import write_log
# from dpi_engine import dpi_packet_callback  # DPI Engine Integration

# # -----------------------------
# # Load Configuration Files
# # -----------------------------
# with open('firewall_rules.json') as rules_file:
#     firewall_rules = json.load(rules_file)["rules"]

# with open('blocklist.json') as blocklist_file:
#     blocklist = set(json.load(blocklist_file)["blocklist"])

# # -----------------------------
# # Detect Interface with MAC Matching
# # -----------------------------
# def get_interface_guid():
#     active_interface = None
#     wifi_mac = None

#     for interface, addrs in psutil.net_if_addrs().items():
#         for addr in addrs:
#             if addr.family == psutil.AF_LINK:
#                 if "Wi-Fi" in interface:
#                     active_interface = interface
#                     wifi_mac = addr.address.replace(":", "-").lower()
#                     break

#     if not active_interface or not wifi_mac:
#         print("[ERROR] No active Wi-Fi interface detected.")
#         return None

#     print(f"[INFO] Active Interface Detected (psutil): {active_interface} | MAC: {wifi_mac}")

#     for iface in get_if_list():
#         try:
#             scapy_mac = get_if_hwaddr(iface).replace(":", "-").lower()
#             if scapy_mac == wifi_mac:
#                 print(f"[INFO] Matched Interface Found: {iface}")
#                 return iface
#         except Exception:
#             continue

#     print("[WARNING] Automatic detection failed. Showing available interfaces:")
#     for idx, iface in enumerate(get_if_list(), start=1):
#         print(f"{idx}. {iface}")

#     choice = input("[INPUT] Select the correct interface (Enter the number): ")
#     try:
#         return get_if_list()[int(choice) - 1]
#     except (IndexError, ValueError):
#         print("[ERROR] Invalid selection.")
#         return None

# # -----------------------------
# # Restart Npcap Service
# # -----------------------------
# def restart_npcap():
#     try:
#         subprocess.run(['sc', 'stop', 'npcap'], check=True)
#         time.sleep(5)
#         subprocess.run(['sc', 'start', 'npcap'], check=True)
#         time.sleep(5)
#         print("[INFO] Npcap service restarted successfully.")
#     except subprocess.CalledProcessError:
#         print("[WARNING] Npcap restart failed. Please restart manually if required.")

# # -----------------------------
# # GeoIP Lookup for IP Location
# # -----------------------------
# # def get_geoip_info(ip_address):
# #     API_URL = f"https://ipinfo.io/{ip_address}/json?token=1f20023fd681f2"

# #     try:
# #         response = requests.get(API_URL, timeout=5)
# #         response.raise_for_status()

# #         data = response.json()
# #         country = data.get('country', 'Unknown')
# #         return country

# #     except requests.exceptions.RequestException:
# #         return "Unknown"

# def get_geoip_info(ip_address):
#     # Check for Private, Multicast, or Broadcast IPs
#     ip = ipaddress.ip_address(ip_address)

#     if ip.is_private:
#         return "Private IP"
#     if ip.is_multicast:
#         return "Multicast"
#     if ip.is_unspecified or ip.is_reserved:
#         return "Reserved IP"
#     if ip_address == "255.255.255.255":
#         return "Broadcast"

#     # Primary API: ipinfo.io
#     try:
#         response = requests.get(f"https://ipinfo.io/{ip_address}/json?token=1f20023fd681f2", timeout=5)
#         if response.status_code == 200:
#             data = response.json()
#             city = data.get('city', 'Unknown')
#             region = data.get('region', 'Unknown')
#             country = data.get('country', 'Unknown')
#             org = data.get('org', 'Unknown ISP/Org')
#             return f"{city}, {region}, {country} ({org})"
#     except requests.exceptions.RequestException:
#         pass  # Fallback to the second API

#     # Fallback API: ip-api.com (More reliable for some regions)
#     try:
#         response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
#         if response.status_code == 200:
#             data = response.json()
#             city = data.get('city', 'Unknown')
#             region = data.get('regionName', 'Unknown')
#             country = data.get('country', 'Unknown')
#             isp = data.get('isp', 'Unknown ISP/Org')
#             return f"{city}, {region}, {country} ({isp})"
#     except requests.exceptions.RequestException:
#         pass  # If both APIs fail

#     return "Unknown"

# # -----------------------------
# # Example Usage
# # -----------------------------
# if __name__ == "__main__":
#     test_ips = [
#         "8.8.8.8",           # Public IP (Google DNS)
#         "172.16.0.1",        # Private IP
#         "224.0.0.251",       # Multicast IP
#         "255.255.255.255",   # Broadcast IP
#         "45.33.32.156",      # Example Public IP
#         "192.168.1.1"        # Private IP
#     ]

#     for ip in test_ips:
#         print(f"{ip} --> {get_geoip_info(ip)}")

# # -----------------------------
# # Notification System
# # -----------------------------
# def show_notification(title, message):
#     notification.notify(
#         title=title,
#         message=message,
#         app_name="Firewall Alert",
#         timeout=10
#     )

# # -----------------------------
# # Packet Filtering Logic (Updated with DPI Integration)
# # -----------------------------

# def packet_callback(packet):
#     # Ignore non-IP packets
#     if not packet.haslayer(IP):
#         return  

#     # Ignore packets with empty payloads
#     if packet.haslayer(Raw) and not packet[Raw].load:
#         return  

#     ip_src = packet[IP].src
#     ip_dst = packet[IP].dst
#     src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else "N/A"
#     dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else "N/A"

#     protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"

#     # GeoIP Location Information
#     src_location = get_geoip_info(ip_src)
#     dst_location = get_geoip_info(ip_dst)

#     # DPI Integration - Deep Packet Inspection for Malicious Patterns
#     is_suspicious, details = dpi_packet_callback(packet)
#     if is_suspicious:
#         alert_message = (f"[ALERT] Suspicious Packet: {ip_src}:{src_port} --> {ip_dst}:{dst_port} | "
#                          f"Protocol: {protocol} | Location: {src_location} -> {dst_location} | Details: {details}")
#         print(alert_message)
#         show_notification("Firewall Alert", alert_message)
#         write_log("alert", alert_message)
#         return  

#     # Blocklist Checking
#     if ip_src in blocklist or ip_dst in blocklist:
#         blocked_message = (f"[BLOCKED] {ip_src}:{src_port} --> {ip_dst}:{dst_port} | "
#                            f"Protocol: {protocol} | Location: {src_location} -> {dst_location} (Blocklist Match)")
#         print(blocked_message)
#         write_log("blocked", blocked_message)
#         return  

#     # Firewall Rules Processing
#     for rule in firewall_rules:
#         conditions = rule["conditions"]

#         # IP-based Blocking
#         if "ip" in conditions and (ip_src in conditions["ip"] or ip_dst in conditions["ip"]):
#             if rule["action"] == "block":
#                 blocked_message = (f"[BLOCKED] {ip_src}:{src_port} --> {ip_dst}:{dst_port} | "
#                                    f"Rule: {rule['rule_name']} | Location: {src_location} -> {dst_location}")
#                 print(blocked_message)
#                 write_log("blocked", blocked_message)
#                 return
#             elif rule["action"] == "alert":
#                 alert_message = (f"[ALERT] {ip_src}:{src_port} --> {ip_dst}:{dst_port} | "
#                                  f"Rule: {rule['rule_name']} | Location: {src_location} -> {dst_location}")
#                 print(alert_message)
#                 write_log("alert", alert_message)

#     # Allow Remaining Traffic
#     allowed_message = (f"[ALLOWED] {ip_src}:{src_port} --> {ip_dst}:{dst_port} | "
#                        f"Protocol: {protocol} | Location: {src_location} -> {dst_location}")
#     print(allowed_message)
#     write_log("allowed", allowed_message)



# # def packet_callback(packet):
# #     if IP in packet:
# #         ip_src = packet[IP].src
# #         ip_dst = packet[IP].dst
# #         protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"

# #         # Blocklist Checking
# #         if ip_src in blocklist or ip_dst in blocklist:
# #             print(f"[BLOCKED] {ip_src} --> {ip_dst} | Protocol: {protocol} (Blocklist Match)")
# #             write_log("blocked", f"{ip_src} --> {ip_dst} | Protocol: {protocol} (Blocklist Match)")
# #             return

# #         # DPI Integration - Deep Packet Inspection for Malicious Patterns
# #         is_suspicious, details = dpi_packet_callback(packet)
# #         if is_suspicious:
# #             alert_message = f"[ALERT] Suspicious Packet: {ip_src} --> {ip_dst} | Details: {details}"
# #             print(alert_message)
# #             show_notification("Firewall Alert", alert_message)
# #             write_log("alert", alert_message)
# #             return

# #         # Firewall Rules Processing
# #         for rule in firewall_rules:
# #             conditions = rule["conditions"]

# #             # IP-based Blocking
# #             if "ip" in conditions and (ip_src in conditions["ip"] or ip_dst in conditions["ip"]):
# #                 if rule["action"] == "block":
# #                     print(f"[BLOCKED] {ip_src} --> {ip_dst} | Rule: {rule['rule_name']}")
# #                     write_log("blocked", f"{ip_src} --> {ip_dst} | Rule: {rule['rule_name']}")
# #                     return
# #                 elif rule["action"] == "alert":
# #                     print(f"[ALERT] {ip_src} --> {ip_dst} | Rule: {rule['rule_name']}")
# #                     write_log("alert", f"{ip_src} --> {ip_dst} | Rule: {rule['rule_name']}")

# #         # Allow Remaining Traffic
# #         print(f"[ALLOWED] {ip_src} --> {ip_dst} | Protocol: {protocol}")
# #         write_log("allowed", f"{ip_src} --> {ip_dst} | Protocol: {protocol}")

# # -----------------------------
# # Start Sniffing
# # -----------------------------
# def start_sniffing():
#     selected_interface = get_interface_guid()
#     if selected_interface:
#         print(f"[INFO] Starting packet sniffing on interface: {selected_interface}")
#         sniff(iface=selected_interface, prn=packet_callback, store=0)
#     else:
#         print("[ERROR] Could not detect the correct interface.")

# # -----------------------------
# # Main Execution
# # -----------------------------
# if __name__ == "__main__":
#     restart_npcap()
#     start_sniffing()
