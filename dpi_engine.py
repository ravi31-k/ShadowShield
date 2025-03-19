import re
from scapy.all import Raw

# Predefined suspicious patterns for DPI (customizable)
SUSPICIOUS_PATTERNS = [
    rb"(?:\x00\x00\x00\x00\x00\x00\x00\x00)",  # Null-byte overflow pattern
    rb"password\s*=\s*\w+",                     # Password leakage pattern
    rb"admin\s*=\s*\w+",                        # Admin credential pattern
    rb"(?:\x90\x90\x90\x90)",                   # NOP sled (common in buffer overflow attacks)
    rb"GET\s+/etc/passwd",                      # Attempt to access system files
    rb"cmd.exe",                                # Windows command shell pattern
    rb"powershell",                             # PowerShell execution pattern
    rb"bash\s+-i",                              # Reverse shell attempt
]

# DPI Engine for Packet Analysis
def dpi_packet_callback(packet):
    if packet.haslayer(Raw):  
        payload = packet[Raw].load
        if not payload:   # <-- Added check for empty payloads
            return False, "Empty Payload (Safe)"

        # Scan payload against suspicious patterns
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, payload):
                return True, f"Suspicious payload detected: {pattern.decode(errors='ignore')}"

    return False, "Clean packet"
