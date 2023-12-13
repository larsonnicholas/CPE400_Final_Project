from scapy.all import *
from collections import Counter
import numpy as np
import pandas as pd

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
total_IPs = len(sourceIPs)
sourceIP_counts = Counter(sourceIPs)
sourceIP_probabilities = {ip: count / total_IPs for ip, count in sourceIP_counts.items()}

df_source_ips = pd.DataFrame({
    'Source IP': sourceIP_counts.keys(),
    'Count': sourceIP_counts.values(),
    'Probability': sourceIP_probabilities.values()
})

excel_filename_source_ips = 'source_ips_probabilities.xlsx'
df_source_ips.to_excel(excel_filename_source_ips, index=False)

print(f"\nSource IP counts and probabilities have been written to {excel_filename_source_ips}")

destIPs = [packet[IP].dst for packet in packets if IP in packet]


#Port Analysis
sourcePorts = [packet[TCP].sport for packet in packets if TCP in packet]
total_source_ports = len(sourcePorts)
sourcePort_counts = Counter(sourcePorts)
sourcePort_probabilities = {port: count / total_source_ports for port, count in sourcePort_counts.items()}

df_source_ports = pd.DataFrame({
    'Source Port': sourcePort_counts.keys(),
    'Count': sourcePort_counts.values(),
    'Probability': sourcePort_probabilities.values()
})

excel_filename_source_ports = 'source_ports_probabilities.xlsx'
df_source_ports.to_excel(excel_filename_source_ports, index=False)

destPorts = [packet[TCP].dport for packet in packets if TCP in packet]
total_dest_ports = len(destPorts)
destPort_counts = Counter(destPorts)
destPort_probabilities = {port: count / total_dest_ports for port, count in destPort_counts.items()}

df_dest_ports = pd.DataFrame({
    'Destination Port': destPort_counts.keys(),
    'Count': destPort_counts.values(),
    'Probability': destPort_probabilities.values()
})

excel_filename_dest_ports = 'dest_ports_probabilities.xlsx'
df_dest_ports.to_excel(excel_filename_dest_ports, index=False)

print(f"Source port counts and probabilities have been written to {excel_filename_source_ports}")
print(f"Destination port counts and probabilities have been written to {excel_filename_dest_ports}")

#Protocol Distribution
protocols = [packet[IP].proto for packet in packets if IP in packet]
protocolNames = {
    6: 'TCP',
    17: 'UDP',
    1: 'ICMP'
}
protocols = [protocolNames.get(proto, proto) for proto in protocols]
protocolCounts = Counter(protocols)

application_ports = {
    53: 'DNS',
    80: 'HTTP',
    443: 'HTTPS',
    21: 'FTP',
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP'
}
application_layer_protocols = Counter()

for packet in packets:
    if IP in packet:
        if TCP in packet:
            if packet[TCP].dport in application_ports:
                application_layer_protocols[application_ports[packet[TCP].dport]] += 1
            elif packet[TCP].sport in application_ports:
                application_layer_protocols[application_ports[packet[TCP].sport]] += 1
        elif UDP in packet:
            if packet[UDP].dport in application_ports:
                application_layer_protocols[application_ports[packet[UDP].dport]] += 1
            elif packet[UDP].sport in application_ports:
                application_layer_protocols[application_ports[packet[UDP].sport]] += 1

# Transport Layer Protocol Distribution
total_transport_packets = len(protocols)
transport_protocol_probabilities = {proto: count / total_transport_packets for proto, count in protocolCounts.items()}

df_transport_protocols = pd.DataFrame({
    'Protocol': protocolCounts.keys(),
    'Count': protocolCounts.values(),
    'Probability': transport_protocol_probabilities.values()
})
excel_filename_transport_protocols = 'transport_layer_protocols_probabilities.xlsx'
df_transport_protocols.to_excel(excel_filename_transport_protocols, index=False)

total_application_packets = sum(application_layer_protocols.values())
application_protocol_probabilities = {proto: count / total_application_packets for proto, count in application_layer_protocols.items()}

df_application_protocols = pd.DataFrame({
    'Protocol': application_layer_protocols.keys(),
    'Count': application_layer_protocols.values(),
    'Probability': application_protocol_probabilities.values()
})

excel_filename_application_protocols = 'application_layer_protocols_probabilities.xlsx'
df_application_protocols.to_excel(excel_filename_application_protocols, index=False)

print(f"Transport layer protocol probabilities have been written to {excel_filename_transport_protocols}")
print(f"Application layer protocol probabilities have been written to {excel_filename_application_protocols}")

#Packet Length

packet_lengths = [len(packet) for packet in packets]
total_volume = sum(packet_lengths)
total_packet_count = len(packet_lengths)
average_packet_size = total_volume / totalPackets if totalPackets else 0
packet_length_counts = Counter(packet_lengths)
packet_length_probabilities = {length: count / total_packet_count for length, count in packet_length_counts.items()}

df = pd.DataFrame(list(packet_length_probabilities.items()), columns=['Packet Length', 'Probability'])

excel_filename = 'packet_length_probabilities.xlsx'
df.to_excel(excel_filename, index=False)

print(f"Packet length probabilities have been written to {excel_filename}")

#Window Size
window_sizes = [packet[TCP].window for packet in packets if TCP in packet]
total_window_sizes = len(window_sizes)
window_size_counts = Counter(window_sizes)
window_size_probabilities = {size: count / total_window_sizes for size, count in window_size_counts.items()}

df_window_sizes = pd.DataFrame({
    'Window Size': window_size_counts.keys(),
    'Count': window_size_counts.values(),
    'Probability': window_size_probabilities.values()
})

excel_filename_window_sizes = 'window_sizes_probabilities.xlsx'
df_window_sizes.to_excel(excel_filename_window_sizes, index=False)

print(f"Window size counts and probabilities have been written to {excel_filename_window_sizes}")

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

# TCP Flags Analysis
tcp_flags_distribution = Counter()
for packet in packets:
    if TCP in packet:
        flags = packet[TCP].flags
        flags_str = ''.join(sorted(f for f in 'FSRPAUEC' if getattr(packet[TCP].flags, f)))
        tcp_flags_distribution[flags_str] += 1

total_tcp_flags = sum(tcp_flags_distribution.values())
tcp_flag_probabilities = {flags: count / total_tcp_flags for flags, count in tcp_flags_distribution.items()}

df_tcp_flags = pd.DataFrame({
    'TCP Flags': tcp_flags_distribution.keys(),
    'Count': tcp_flags_distribution.values(),
    'Probability': tcp_flag_probabilities.values()
})

excel_filename_tcp_flags = 'tcp_flags_probabilities.xlsx'
df_tcp_flags.to_excel(excel_filename_tcp_flags, index=False)

print(f"TCP flag combinations and probabilities have been written to {excel_filename_tcp_flags}")

#RTT Analysis
seq_sent_times = defaultdict(dict)
stream_rtts = defaultdict(list)

for packet in packets:
    if TCP in packet and IP in packet:
        stream_id = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
        if packet[TCP].flags & 0x17:
            seq_sent_times[stream_id][packet[TCP].seq] = packet.time

for packet in packets:
    if TCP in packet and IP in packet:
        stream_id = (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
        if packet[TCP].flags & 0x10:
            for seq, time_sent in seq_sent_times[stream_id].items():
                if seq < packet[TCP].ack:
                    rtt = packet.time - time_sent
                    stream_rtts[stream_id].append(rtt)
                    del seq_sent_times[stream_id][seq]
                    break

for stream_id, rtts in stream_rtts.items():
    positive_rtts = [abs(float(rtt)) for rtt in rtts if rtt >= 0]
    if positive_rtts: 
        average_rtt = np.mean(positive_rtts)
        max_rtt = np.max(positive_rtts)
        min_rtt = np.min(positive_rtts)

        print(f"\nStream {stream_id} - RTT measurements:")
        print(f"  Average RTT: {average_rtt:.6f} seconds")
        print(f"  Max RTT: {max_rtt:.6f} seconds")
        print(f"  Min RTT: {min_rtt:.6f} seconds")
        print(f"  RTT measurements: {len(positive_rtts)}")