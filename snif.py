import psutil
from scapy.all import sniff, get_if_list

# Extract MAC Address from psutil
def get_wifi_mac():
    for adapter in psutil.net_if_addrs().items():
        name, addrs = adapter
        for addr in addrs:
            if "wi-fi" in name.lower() and addr.family == psutil.AF_LINK:
                return addr.address
    return None

# Map Scapy Interfaces to MAC Addresses
def get_interface_guid():
    wifi_mac = get_wifi_mac()
    if not wifi_mac:
        print("[ERROR] No Wi-Fi MAC found.")
        return None

    # Search for matching MAC address in Scapy's interfaces
    for iface in get_if_list():
        if wifi_mac.replace(":", "-").upper() in iface:
            return iface

    print("[WARNING] Automatic detection failed. Showing available interfaces:")
    available_interfaces = get_if_list()
    for idx, iface in enumerate(available_interfaces, 1):
        print(f"{idx}. {iface}")

    # Manual Selection (Fallback)
    choice = int(input("[INPUT] Select the correct interface (Enter the number): "))
    return available_interfaces[choice - 1] if 0 < choice <= len(available_interfaces) else None

# Sample packet callback
def packet_callback(packet):
    print(f"[INFO] Packet captured: {packet.summary()}")

# Start Sniffing
def start_sniffing():
    selected_interface = get_interface_guid()
    if selected_interface:
        print(f"[INFO] Starting packet sniffing on interface: {selected_interface}")
        sniff(iface=selected_interface, prn=packet_callback, store=0)
    else:
        print("[ERROR] No active network interface found.")

if __name__ == "__main__":
    start_sniffing()
