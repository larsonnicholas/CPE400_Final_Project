from scapy.all import *
from collections import Counter
import numpy as np

packets = rdpcap("./RingCamera_PacketCapture.pcapng")

#Traffic Volume Analysis
totalPackets = len(packets)
print(f"\nTotal packets: {totalPackets}")

#Stream Index
streams = {}
stream_packet_counts = {}

for packet in packets:
    if IP in packet and TCP in packet:
        #Source IP, Source Port, Destination IP, Destination Port
        stream_tuple = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
        reverse_tuple = (packet[IP].dst, packet[TCP].dport, packet[IP].src, packet[TCP].sport) 
        if stream_tuple not in streams and reverse_tuple not in streams:
            streams[stream_tuple] = len(streams) + 1  
            stream_packet_counts[streams[stream_tuple]] = 1
        else:
            current_stream_index = streams.get(stream_tuple) or streams.get(reverse_tuple)
            stream_packet_counts[current_stream_index] += 1
print("\nTCP Stream Information:")
for stream, index in streams.items():
    print(f"Stream {index}: {stream} - Packets: {stream_packet_counts[index]}")

#Source and Destination Analysis
sourceIPs = [packet[IP].src for packet in packets if IP in packet]
destIPs = [packet[IP].dst for packet in packets if IP in packet]

topSourceIPs = Counter(sourceIPs).most_common(5)
topDestIPs = Counter(destIPs).most_common(5)

print("\nTop Source IPs:")
for ip, count in topSourceIPs:
    print(f"{ip}: {count} packets")

print("\nTop Destination IPs:")
for ip, count in topDestIPs:
    print(f"{ip}: {count} packets")

#Port Analysis
destPorts = [packet[TCP].dport for packet in packets if TCP in packet]
topDestPorts = Counter(destPorts).most_common(5)

print("\nTop Destination Ports:")
for port, count in topDestPorts:
    print(f"{port}: {count} appearances")

#Protocol Distribution
protocols = [packet[IP].proto for packet in packets if IP in packet]
protocolNames = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
protocols = [protocolNames.get(proto, proto) for proto in protocols]
protocolCounts = Counter(protocols)

print("\nProtocol Distribution:")
for protocol, count in protocolCounts.items():
    print(f"{protocol}: {count} packets")

#Packet Length
packet_lengths = [len(packet) for packet in packets]
total_volume = sum(packet_lengths)

print(f"\nTotal data volume: {total_volume} bytes")
top_packet_lengths = Counter(packet_lengths).most_common(5)

print("\nTop Packet Lengths:")
for length, count in top_packet_lengths:
    print(f"Length {length}: {count} packets")

average_packet_size = total_volume / totalPackets if totalPackets else 0

print(f"\nAverage packet size: {average_packet_size} bytes")

#Window Size
window_sizes = [packet[TCP].window for packet in packets if TCP in packet]

if window_sizes:
    average_window_size = sum(window_sizes) / len(window_sizes)
else:
    average_window_size = 0

print(f"\nAverage TCP Window Size: {average_window_size}")
top_window_sizes = Counter(window_sizes).most_common(5)

print("\nTop TCP Window Sizes:")
for window_size, count in top_window_sizes:
    print(f"Window Size {window_size}: {count} packets")

#TCP Flags
tcp_flags_distribution = Counter()

for packet in packets:
    if TCP in packet:
        flags = packet[TCP].flags
        flags_str = ''
        if flags & 0x01: flags_str += 'F'  # FIN
        if flags & 0x02: flags_str += 'S'  # SYN
        if flags & 0x04: flags_str += 'R'  # RST
        if flags & 0x08: flags_str += 'P'  # PSH
        if flags & 0x10: flags_str += 'A'  # ACK
        if flags & 0x20: flags_str += 'U'  # URG
        if flags & 0x40: flags_str += 'E'  # ECE
        if flags & 0x80: flags_str += 'C'  # CWR
        tcp_flags_distribution[flags_str] += 1
        
print("\nTCP Flags Distribution:")
for flags, count in tcp_flags_distribution.items():
    print(f"{flags}: {count} packets")