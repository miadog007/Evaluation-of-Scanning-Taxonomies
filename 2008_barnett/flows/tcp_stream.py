import dpkt
import socket
from collections import defaultdict

def tcp_stream(key, data, tcp_streams):

    # TCP flags of interest
    TCP_FLAGS = {
    'FIN': dpkt.tcp.TH_FIN,
    'SYN': dpkt.tcp.TH_SYN, 
    'ACK': dpkt.tcp.TH_ACK
     }
    
    # Sort packets in each stream by timestamp
    for key in tcp_streams:
        tcp_streams[key].sort()

    # Process each stream
    for key, packets in tcp_streams.items():
        flags = set()
        times = []

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