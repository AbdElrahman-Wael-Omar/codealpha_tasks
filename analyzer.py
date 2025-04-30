import matplotlib.pyplot as plt
from collections import defaultdict

protocol_stats = defaultdict(int)

def update_protocol_stats(protocol):
    protocol_stats[protocol] += 1

def show_protocol_chart():
    if not protocol_stats:
        print("No protocols recorded yet.")
        return

    labels = list(protocol_stats.keys())
    sizes = list(protocol_stats.values())

    plt.figure(figsize=(6, 6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title("Protocol Distribution")
    plt.axis('equal')
    plt.tight_layout()
    plt.show()