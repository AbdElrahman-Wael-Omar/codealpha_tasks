from sniffer import start_sniff
from gui import create_gui

def start_sniffing(callback, protocol_filter):
    start_sniff(callback, protocol_filter)

def stop_sniffing():
    pass

if __name__ == "__main__":
    create_gui(start_sniffing, stop_sniffing)