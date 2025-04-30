from scapy.all import sniff

def start_sniff(callback, protocol_filter=""):
    sniff(prn=callback, store=False, filter=protocol_filter)

def stop_sniff():
    pass