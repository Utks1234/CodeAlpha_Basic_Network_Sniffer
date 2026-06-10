from scapy.all import *

def packet_callback(packet):
    print("\n" + "="*80)

    if packet.haslayer(IP):
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        raw_data = bytes(packet)
        print(f"Packet Size    : {len(raw_data)} bytes")

        print("\nRaw Packet Data:")
        print(raw_data[:100])

sniff(prn=packet_callback, store=False)