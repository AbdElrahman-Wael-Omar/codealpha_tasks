import csv
import json
import datetime

LOG_TXT = "packet_log.txt"
LOG_CSV = "packet_log.csv"
LOG_JSON = "packet_log.json"

def log_to_txt(packet_summary):
    with open(LOG_TXT, "a") as f:
        f.write(packet_summary + "\n")

def export_to_csv(data_list):
    with open(LOG_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=data_list[0].keys())
        writer.writeheader()
        writer.writerows(data_list)

def export_to_json(data_list):
    with open(LOG_JSON, "w") as f:
        json.dump(data_list, f, indent=4)