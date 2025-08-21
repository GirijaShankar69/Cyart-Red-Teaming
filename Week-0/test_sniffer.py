
from scapy.all import *
from collections import Counter
import matplotlib.pyplot as plt

def main():    
    interface = "eth0"
    print(f"[+] Sniffing 100 packets on interface: {interface}...")
    
    # Sniff exactly 100 packets.
    try:
        packets = sniff(count=100, iface=interface)
        print("[+] Packet capture complete.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")
        return

    protocol_list = []
    
    for packet in packets:
        if packet.haslayer(TCP):
            protocol_list.append("TCP")
        elif packet.haslayer(UDP):
            protocol_list.append("UDP")
        elif packet.haslayer(ICMP):
            protocol_list.append("ICMP")
        elif packet.haslayer(ARP):
            protocol_list.append("ARP")

    protocol_counts = Counter(protocol_list)
    
    print("\n--- Protocol Summary ---")
    for protocol, count in protocol_counts.items():
        print(f"{protocol}: {count} packets")
        

    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())

    # Create the bar chart.
    plt.figure(figsize=(10, 6))
    plt.bar(protocols, counts, color=['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728'])
    plt.title('Network Protocol Distribution')
    plt.xlabel('Protocol')
    plt.ylabel('Number of Packets')
    
    # Save the chart to a file.
    chart_filename = "protocol_distribution.png"
    plt.savefig(chart_filename)
    
    print(f"\n[+] Bar chart saved as {chart_filename}")


if __name__ == "__main__":
    main()
