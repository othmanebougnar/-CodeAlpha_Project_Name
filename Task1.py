from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP


def explain_packet(packet):
    print("\n📦 New Packet Captured:")

    # Check if the packet contains an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ttl = packet[IP].ttl
        proto = packet[IP].proto

        print(f"   🌐 Source IP: {src_ip}  ➝  Destination IP: {dst_ip}")
        print(f"   🔢 TTL (Time To Live): {ttl} (Limits how long the packet can travel)")
        print(f"   📡 Protocol Number: {proto} (Identifies the transport protocol)")

        # Check if the packet contains a TCP layer
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags

            print(f"   🔵 Protocol: TCP (Reliable, connection-oriented)")
            print(f"   🚪 Source Port: {src_port}  ➝  Destination Port: {dst_port}")
            print(f"   🚩 TCP Flags: {flags} (Indicates connection state)")

        # Check if the packet contains a UDP layer
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            print(f"   🟢 Protocol: UDP (Fast, connectionless)")
            print(f"   🚪 Source Port: {src_port}  ➝  Destination Port: {dst_port}")

        # Check if the packet contains an ICMP layer
        elif ICMP in packet:
            print(f"   ⚡ Protocol: ICMP (Used for network diagnostics, like ping)")

        # Extract payload (data)
        payload_data = packet.payload
        if len(payload_data) > 0:
            print(f"   📄 Payload (Data inside the packet): {payload_data}")
        else:
            print("   🚫 No Payload (Control packet)")

        print("   📑 Full Packet Details:\n")
        packet.show()  # Show full Scapy packet details with structure
        print("=" * 80)  # Separator for readability


print("🚀 Starting Network Sniffer... Press Ctrl+C to stop.")
sniff(prn=explain_packet)  # Capture packets indefinitely
