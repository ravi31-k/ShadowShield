# import json
# import psutil
# import requests
# import subprocess
# import time
# from collections import defaultdict
# from plyer import notification
# from scapy.all import sniff, IP, TCP, UDP, get_if_list, get_if_hwaddr
# from log_manager import write_log

# # -----------------------------
# # Detect Interface with MAC Matching
# # -----------------------------
# def get_interface_guid():
#     active_interface = None
#     wifi_mac = None

#     # Step 1: Identify active Wi-Fi interface & MAC address
#     for interface, addrs in psutil.net_if_addrs().items():
#         for addr in addrs:
#             if addr.family == psutil.AF_LINK:  # MAC Address detection
#                 if "Wi-Fi" in interface:
#                     active_interface = interface
#                     wifi_mac = addr.address.replace(":", "-").lower()
#                     break

#     if not active_interface or not wifi_mac:
#         print("[ERROR] No active Wi-Fi interface detected.")
#         return None

#     print(f"[INFO] Active Interface Detected (psutil): {active_interface} | MAC: {wifi_mac}")

#     # Step 2: Match with Scapy’s Interfaces via MAC Address
#     for iface in get_if_list():
#         try:
#             scapy_mac = get_if_hwaddr(iface).replace(":", "-").lower()
#             if scapy_mac == wifi_mac:
#                 print(f"[INFO] Matched Interface Found: {iface}")
#                 return iface
#         except Exception:
#             continue

#     # Step 3: Fallback - Ask User to Select Interface
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
#         time.sleep(5)  # Delay for stability
#         subprocess.run(['sc', 'start', 'npcap'], check=True)
#         time.sleep(5)  # Delay for stability
#         print("[INFO] Npcap service restarted successfully.")
#     except subprocess.CalledProcessError:
#         print("[WARNING] Npcap restart failed. Please restart manually if required.")

# # -----------------------------
# # GeoIP Lookup for IP Location
# # -----------------------------
# def get_geoip_info(ip_address):
#     API_URL = f"https://ipinfo.io/{ip_address}/json?token=1f20023fd681f2"
    
#     try:
#         response = requests.get(API_URL, timeout=5)
#         response.raise_for_status()

#         data = response.json()
#         city = data.get('city', 'Unknown')
#         region = data.get('region', 'Unknown')
#         country = data.get('country', 'Unknown')
#         org = data.get('org', 'Unknown ISP/Organization')

#         return f"{city}, {region}, {country} ({org})"

#     except requests.exceptions.Timeout:
#         return "[ERROR] GeoIP Lookup Timed Out"

#     except requests.exceptions.RequestException:
#         return "[ERROR] Failed to fetch GeoIP info"

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
# # Packet Filtering Logic
# # -----------------------------
# def packet_callback(packet):
#     if IP in packet:
#         ip_src = packet[IP].src
#         ip_dst = packet[IP].dst
#         protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"

#         src_location = get_geoip_info(ip_src)
#         dst_location = get_geoip_info(ip_dst)

#         print(f"[ALLOWED] {ip_src} --> {ip_dst} | Protocol: {protocol}")
#         write_log("allowed", f"{ip_src} --> {ip_dst} | Protocol: {protocol}")

#         # Alert for suspicious activity (Example Logic)
#         if "China" in dst_location or "Russia" in dst_location:
#             alert_message = f"Suspicious Traffic from {ip_src} ({src_location}) to {ip_dst} ({dst_location})"
#             show_notification("Firewall Alert", alert_message)
#             write_log("alert", alert_message)

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


import json
import psutil
import requests
import subprocess
import time
from collections import defaultdict
from plyer import notification
from scapy.all import sniff, IP, TCP, UDP, get_if_list, get_if_hwaddr
from log_manager import write_log
import ipaddress

# -----------------------------
# Detect Interface with MAC Matching
# -----------------------------
def get_interface_guid():
    active_interface = None
    wifi_mac = None

    # Step 1: Identify active Wi-Fi interface & MAC address
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == psutil.AF_LINK:  # Correct for Windows MAC Address detection
                if "Wi-Fi" in interface:
                    active_interface = interface
                    wifi_mac = addr.address.replace(":", "-").lower()
                    break

    if not active_interface or not wifi_mac:
        print("[ERROR] No active Wi-Fi interface detected.")
        return None

    print(f"[INFO] Active Interface Detected (psutil): {active_interface} | MAC: {wifi_mac}")

    # Step 2: Match with Scapy’s Interfaces via MAC Address
    for iface in get_if_list():
        try:
            scapy_mac = get_if_hwaddr(iface).replace(":", "-").lower()
            if scapy_mac == wifi_mac:
                print(f"[INFO] Matched Interface Found: {iface}")
                return iface
        except Exception:
            continue

    # Step 3: Fallback - Ask User to Select Interface
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
        time.sleep(3)  # Minor delay for stability

        # Confirm Npcap stopped before starting
        for _ in range(3):
            result = subprocess.run(['sc', 'query', 'npcap'], capture_output=True, text=True)
            if 'STOPPED' in result.stdout:
                break
            time.sleep(2)

        subprocess.run(['sc', 'start', 'npcap'], check=True)

        # Confirm Npcap is successfully running
        for _ in range(3):
            result = subprocess.run(['sc', 'query', 'npcap'], capture_output=True, text=True)
            if 'RUNNING' in result.stdout:
                print("[INFO] Npcap service restarted successfully.")
                return
            time.sleep(2)

        print("[WARNING] Npcap restart failed. Please restart manually if required.")
    except subprocess.CalledProcessError:
        print("[ERROR] Npcap restart command failed. Please check manually.")

# -----------------------------
# GeoIP Lookup for IP Location
# -----------------------------
def get_geoip_info(ip_address):
    # Step 1: Handle Private IP Addresses
    if ipaddress.ip_address(ip_address).is_private:
        return "Local Network (Private IP)"

    # Step 2: Perform GeoIP Lookup for Public IPs
    API_URL = f"https://ipinfo.io/{ip_address}/json?token=1f20023fd681f2"
    
    try:
        response = requests.get(API_URL, timeout=5)
        response.raise_for_status()

        data = response.json()
        city = data.get('city', 'Unknown')
        region = data.get('region', 'Unknown')
        country = data.get('country', 'Unknown')
        org = data.get('org', 'Unknown ISP/Organization')

        return f"{city}, {region}, {country} ({org})"

    except requests.exceptions.Timeout:
        return "[ERROR] GeoIP Lookup Timed Out"

    except requests.exceptions.RequestException:
        return "[ERROR] Failed to fetch GeoIP info"

# -----------------------------
# Notification System
# -----------------------------
def show_notification(title, message):
    notification.notify(
        title=title,
        message=message,
        app_name="Firewall Alert",
        timeout=10
    )

# -----------------------------
# Packet Filtering Logic
# -----------------------------
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"

        src_location = get_geoip_info(ip_src)
        dst_location = get_geoip_info(ip_dst)

        print(f"[ALLOWED] {ip_src} --> {ip_dst} | Protocol: {protocol} | Location: {dst_location}")
        write_log("allowed", f"{ip_src} --> {ip_dst} | Protocol: {protocol} | Location: {dst_location}")

        # Alert for suspicious activity (Example Logic)
        if "China" in dst_location or "Russia" in dst_location:
            alert_message = f"Suspicious Traffic from {ip_src} ({src_location}) to {ip_dst} ({dst_location})"
            show_notification("Firewall Alert", alert_message)
            write_log("alert", alert_message)


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
