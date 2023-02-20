import dpkt
import socket

# Set parameters
M = 3
R = 50
N1 = 5
N2 = 5
N3 = 15

# Initialize counters
tcp_heavy_port_scan = 0
tcp_light_port_scan = 0
tcp_heavy_network_scan = 0
tcp_light_network_scan = 0
one_flow = 0
small_syn = 0
other_tcp = 0

# Iterate through packets in pcap file
with open('data/CaptureOne.pcap', 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            # Skip non-IP packets
            continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            # Skip non-TCP packets
            continue
        tcp = ip.data

        # Calculate packet and flag counts
        pkt_count = 1
        syn_count = tcp.flags & dpkt.tcp.TH_SYN != 0
        ack_count = tcp.flags & dpkt.tcp.TH_ACK != 0
        rst_count = tcp.flags & dpkt.tcp.TH_RST != 0
        fin_count = tcp.flags & dpkt.tcp.TH_FIN != 0
        urg_count = tcp.flags & dpkt.tcp.TH_URG != 0
        xmas_count = tcp.flags & dpkt.tcp.TH_PUSH != 0 and \
                     tcp.flags & dpkt.tcp.TH_FIN != 0 and \
                     tcp.flags & dpkt.tcp.TH_URG != 0
        scan_flag_count = syn_count + ack_count + rst_count + fin_count + urg_count + xmas_count
        dst_port = tcp.dport
        dst_ip = socket.inet_ntoa(ip.dst)

        # Check for port scans
        if ip.src == ip.dst == 1 and dst_port >= N2 and scan_flag_count / pkt_count >= R / 100:
            avg_pkt_per_port = 1
            if dst_port in tcp_port_counts:
                avg_pkt_per_port = tcp_port_counts[dst_port] / tcp_port_pkt_counts[dst_port]
            if avg_pkt_per_port > M:
                tcp_heavy_port_scan += 1
            else:
                tcp_light_port_scan += 1

        # Check for network scans
        if ip.src == 1 and dst_port == 1 and scan_flag_count / pkt_count >= R / 100:
            avg_pkt_per_ip = 1
            if dst_ip in tcp_ip_counts:
                avg_pkt_per_ip = tcp_ip_counts[dst_ip] / tcp_ip_pkt_counts[dst_ip]
            if avg_pkt_per_ip > M:
                tcp_heavy_network_scan += 1
            else:
                tcp_light_network_scan += 1

        # Check for TCP "one flow"
        if ip.src == ip.dst == 1 and dst_port == 1 and pkt_count > N3:
            one_flow += 1

        # Check for small SYN
        if ip.src == 1 and int(socket.inet_aton(dst_ip).hex(), 16) < N1 and dst_port < N2 \
                and pkt_count <= N3 and syn_count == 1:
            small_syn += 1

        # Check for other TCP
        if ip.src != ip.dst or dst_port not in [1, 21, 22, 23, 25, 80, 443]:
            other_tcp += 1

print(f"TCP Heavy Port Scan: {tcp_heavy_port_scan}")
print(f"TCP Light Port Scan: {tcp_light_port_scan}")
print(f"TCP Heavy Network Scan: {tcp_heavy_network_scan}")
print(f"TCP Light Network Scan: {tcp_light_network_scan}")
print(f"TCP One Flow: {one_flow}")
print(f"Small SYN: {small_syn}")
print(f"Other TCP: {other_tcp}")

print(repr(tcp))
    






