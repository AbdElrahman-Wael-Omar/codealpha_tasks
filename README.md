# codealpha_tasks
Network Sniffer Project 
This project is a Python-based network sniffer tool with a GUI. It uses Scapy to capture packets, Tkinter for
the GUI, and matplotlib for live charts. The application allows protocol filtering, packet logging, and exporting
data to CSV/JSON.
1. sniffer.py
from scapy.all import sniff
def start_sniff(callback, protocol_filter=""):
sniff(prn=callback, store=False, filter=protocol_filter)
def stop_sniff():
      pass
2. logger.py
import csv
import json
import datetime
LOG_TXT = "packet_log.txt"
LOG_CSV = "packet_log.csv"
LOG_JSON = "packet_log.json"
def log_to_txt(packet_summary):
with open(LOG_TXT, "a") as f:
f.write(packet_summary + "\n")
def export_to_csv(data_list):with open(LOG_CSV, "w", newline="") as f:
writer = csv.DictWriter(f, fieldnames=data_list[0].keys())
writer.writeheader()
writer.writerows(data_list)
def export_to_json(data_list):
with open(LOG_JSON, "w") as f:
json.dump(data_list, f, indent=4)
3. gui.py
This file contains the Tkinter GUI layout. It allows protocol filtering, displays logs in a scrolled text area, shows
packets in a TreeView, and supports export buttons and protocol chart visualization.
See full implementation in project codebase.
4. analyzer.py
import matplotlib.pyplot as plt
from collections import defaultdict
protocol_stats = defaultdict(int)
def update_protocol_stats(protocol):
protocol_stats[protocol] += 1
def show_protocol_chart():
if not protocol_stats:
print("No protocols recorded yet.")
returnlabels = list(protocol_stats.keys())
sizes = list(protocol_stats.values())
plt.figure(figsize=(6, 6))
plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
plt.title("Protocol Distribution")
plt.axis('equal')
plt.tight_layout()
plt.show()
5. packet_parser.py
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
"Destination": packet[IP].dst if IP in packet else "N/A","Protocol": get_protocol(packet),
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
6. main.py
from sniffer import start_sniff
from gui import create_gui
def start_sniffing(callback, protocol_filter):
start_sniff(callback, protocol_filter)
def stop_sniffing():
pass
if __name__ == "__main__":create_gui(start_sniffing, stop_sniffing)
