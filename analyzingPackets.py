from scapy.all import *
from collections import Counter

packets = rdpcap("./RingCamera_PacketCapture.pcapng")

#Traffic Volume Analysis
totalPackets = len(packets)
print(f"\nTotal packets: {totalPackets}")

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