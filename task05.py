from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

print("Network Packet Analyzer")
print("Capturing 10 packets...\n")

def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "Other"

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"

        print("Source IP:", src_ip)
        print("Destination IP:", dst_ip)
        print("Protocol:", protocol)

        # Show first 50 bytes of payload (if available)
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet.payload)
            print("Payload (first 50 bytes):", payload[:50])

        print("-" * 50)

# Capture 10 packets
sniff(prn=analyze_packet, count=10)