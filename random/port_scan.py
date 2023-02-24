import dpkt
from collections import defaultdict


def count_packets_per_port(pkt_list):
    packet_counts = defaultdict(int)
    for pkt in pkt_list:
        packet_counts[pkt['dst_port']] += 1
    return packet_counts

def print_port_scan(flow, pkt_list, is_tcp, threshold):
    # Calculate packet count per port
    packet_counts = count_packets_per_port(pkt_list)
    
    # Check if the port scan is heavy or light
    if is_tcp:
        scan_flags = ['F', 'S', 'SA', '']  # FIN, SYN, FIN ACK, NULL
        total_flags = sum(1 for pkt in pkt_list if dpkt.tcp.tcp_flags_to_str(pkt['tcp_flags']) in scan_flags)
        if total_flags == 0:
            return False  # Not a port scan
        elif total_flags / len(pkt_list) > 0.5:
            scan_type = "heavy"
        else:
            scan_type = "light"
    else:
        if len(pkt_list) <= threshold:
            return False  # Not a port scan
        scan_type = "heavy"
    
    # Check if there are enough packets for the scan
    if len(packet_counts) < 5:
        return False  # Not a port scan
    
    # Check if the number of packets per port meets the threshold
    max_packets_per_port = max(packet_counts.values())
    if (scan_type == "heavy" and max_packets_per_port > threshold) or (scan_type == "light" and max_packets_per_port <= threshold):
        # Print port scan info
        print(f"{flow.protocol}, {flow.src}, {flow.dst}, {len(packet_counts)}, {total_flags / len(pkt_list):.2%}, {max(packet_counts, key=packet_counts.get)}")
        return True
    else:
        return False
     


tcp_flows = defaultdict(list)
udp_flows = defaultdict(list)

with open('data/CaptureOne.pcap', 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            key = (ip.src, ip.dst, tcp.dport)
            tcp_flows[key].append({'ts': ts, 'tcp_flags': tcp.flags, 'dst_port': tcp.dport})
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            key = (ip.src, ip.dst, udp.dport)
            udp_flows[key].append({'ts': ts, 'dst_port': udp.dport})
    
    for flow_key, pkt_list in tcp_flows.items():
        if len(pkt_list) >= 2:
            flow = dpkt.tcp.TCP()
            flow.src, flow.dst, flow.dport = flow_key
            flow.protocol = "TCP"
            print_port_scan(flow, pkt_list, True, 3)
            
    for flow_key, pkt_list in udp_flows.items():
        if len(pkt_list) >= 2:
            flow = dpkt.udp.UDP()
            flow.src, flow.dst, flow.dport = flow_key
            flow.protocol = "UDP"
            print_port_scan(flow, pkt_list, False, 3)


