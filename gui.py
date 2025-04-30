import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from threading import Thread
from logger import log_to_txt, export_to_csv, export_to_json
from analyzer import update_protocol_stats, show_protocol_chart
from packet_parser import parse_packet_summary, parse_packet_details

sniffer_thread = None
sniffing = {"value": False}
packet_data_list = []

def create_gui(start_sniff_callback, stop_sniff_callback):
    def start_sniffing():
        sniffing["value"] = True
        packet_data_list.clear()
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)
        protocol = filter_entry.get().strip()
        start_sniff_callback(packet_callback, protocol)

    def stop_sniffing():
        sniffing["value"] = False
        stop_sniff_callback()
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)

    def packet_callback(packet):
        summary = parse_packet_summary(packet)
        details = parse_packet_details(packet)

        log_to_txt(summary)
        packet_data_list.append(details)
        update_protocol_stats(details.get("Protocol", "Other"))

        log_output.insert(tk.END, summary + "\n")
        log_output.see(tk.END)

        tree.insert('', 'end', values=(
            details.get("Time", ""),
            details.get("Source", ""),
            details.get("Destination", ""),
            details.get("Protocol", ""),
            details.get("Length", "")
        ))

    def export_data():
        if packet_data_list:
            export_to_csv(packet_data_list)
            export_to_json(packet_data_list)
            messagebox.showinfo("Export Complete", "Data exported to CSV and JSON.")
        else:
            messagebox.showwarning("No Data", "No packets to export.")

    root = tk.Tk()
    root.title("Python Network Sniffer")

    tk.Label(root, text="Protocol Filter (tcp, udp, icmp):").pack()
    filter_entry = tk.Entry(root, width=50)
    filter_entry.pack(pady=5)

    start_button = tk.Button(root, text="Start Sniffing", command=lambda: Thread(target=start_sniffing).start())
    stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffing, state=tk.DISABLED)
    export_button = tk.Button(root, text="Export Logs", command=export_data)
    chart_button = tk.Button(root, text="Show Protocol Chart", command=show_protocol_chart)

    for btn in [start_button, stop_button, export_button, chart_button]:
        btn.pack(pady=3)

    log_output = scrolledtext.ScrolledText(root, height=10, width=100)
    log_output.pack(pady=5)

    tree = ttk.Treeview(root, columns=("Time", "Source", "Destination", "Protocol", "Length"), show='headings')
    for col in tree["columns"]:
        tree.heading(col, text=col)
        tree.column(col, width=120)
    tree.pack(pady=5)

    root.mainloop()
