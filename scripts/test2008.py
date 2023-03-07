import dpkt
import socket
from collections import defaultdict


TCP_FLAGS = {
    'FIN': dpkt.tcp.TH_FIN,
    'SYN': dpkt.tcp.TH_SYN, 
    'ACK': dpkt.tcp.TH_ACK
     }
# Group packets by source and destination IP addresses and port numbers
tcp_streams = defaultdict(list)

# Open the pcap file
for ts, buf in dpkt.pcap.Reader(open('data/CaptureOne.pcap', 'rb')):
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data


    # Check if the packet is a TCP packet
    if isinstance(tcp, dpkt.tcp.TCP):
        ip_src = socket.inet_ntoa(ip.src)
        ip_dst = socket.inet_ntoa(ip.dst)
        # Group packets together based on source and destination addresses and ports
        key = (ip_src, tcp.sport, ip_dst, tcp.dport)
        tcp_streams[key].append((ts, tcp))

# Sort packets in each stream by timestamp
for key in tcp_streams:
    tcp_streams[key].sort()

# Process each stream
for key, packets in tcp_streams.items():
    flags = set()
    times = []
    avg_time = 0
    num_packets = len(packets)
    first_packet_time = None
    last_packet_time = None

    # Calculate the average and median time between packets
    for i in range(1, len(packets)):
        prev_ts, prev_tcp = packets[i-1]
        ts, tcp = packets[i]
        time_diff = ts - prev_ts
        times.append(time_diff)

        # Get the TCP flags for this packet
        for flag_name, flag_value in TCP_FLAGS.items():
            if tcp.flags & flag_value:
                flags.add(flag_name)

        if last_packet_time is None:
            firs_packet_time = ts
        else:
            times.append(ts - last_packet_time)
        last_packet_time = ts

    if len(times) > 0:
        avg_time = sum(times) / len(times)
        median_time = sorted(times)[len(times) // 2]
    else:
        avg_time = 0

    # Print the results for this stream
    src_ip, src_port, dst_ip, dst_port = key
    print(f"Stream: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    print(f"Flags: {flags}")
    print(f"Average time between packets: {avg_time:.3f} seconds")
    print(f"Median time between packets: {median_time:.3f} seconds")
    print(f"number of packet {num_packets}")
    print(f"first packet {first_packet_time}")
    print(f"last packet: {last_packet_time}")