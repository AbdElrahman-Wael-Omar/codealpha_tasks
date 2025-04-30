from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime

def parse_packet_summary(packet):
    proto = get_protocol(packet)
    src = packet[IP].src if IP in packet else "N/A"
    dst = packet[IP].dst if IP in packet else "N/A"
    timestamp = datetime.now().strftime("%H:%M:%S")
    return f"[{timestamp}] {proto} Packet: {src} -> {dst}"

def parse_packet_details(packet):
    return {
        "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Source": packet[IP].src if IP in packet else "N/A",
        "Destination": packet[IP].dst if IP in packet else "N/A",
        "Protocol": get_protocol(packet),
        "Length": len(packet)
    }

def get_protocol(packet):
    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    elif IP in packet:
        return "IP"
    else:
        return "Other"