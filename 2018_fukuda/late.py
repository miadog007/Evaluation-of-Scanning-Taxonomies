import socket
import dpkt

flows = {}

def tcp_single_flow(packet_data, src_ip, dst_ip):
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.tcp.TCP):
        # Skip non-TCP packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)
    ip_dst = socket.inet_ntoa(ip_packet.dst)

    if ip_src != src_ip or ip_dst != dst_ip:
        # Skip packets that don't match the specified source and destination IP addresses
        return None

    flow_key = (ip_src, ip_dst)

    # Check for flows that exists
    if flow_key in flows:
        # Update the flow information
        flow = flows[flow_key]
        flow['num_packets'] += 1
        flow['dst_ports'].add(ip_packet.data.dport)
    else: 
        # Create new flows
        flow = {
            'src_ip': ip_src,
            'dst_ip': ip_dst,
            'dst_ports': set(),
            'num_packets': 1,
            'scan_packets': 0,
            'syn_packets': 0,
            'frag_packets': 0
        }

        flows[flow_key] = flow

    # Update flags counters
    if ip_packet.data.flags & dpkt.tcp.TH_SYN:
        flow['scan_packets'] += 1
        flow['syn_packets'] += 1
    if ip_packet.data.flags & dpkt.tcp.TH_FIN:
        flow['scan_packets'] += 1
    if ip_packet.data.flags & dpkt.tcp.TH_FIN and ip_packet.data.flags & dpkt.tcp.TH_ACK:
        flow['scan_packets'] += 1
    if not ip_packet.data.flags:
        flow['scan_packets'] += 1

    # Check for fragmented packets
    if ip_packet.data.off & dpkt.ip.IP_OFFMASK != 0:
       flow['frag_packets'] += 1

    
    return flow
    


for ts, pkt in dpkt.pcap.Reader(open('data/CaptureOne.pcap', 'rb')):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
       
    if isinstance(ip, dpkt.ip.IP):
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            flow = tcp_single_flow(pkt, src_ip, dst_ip)
            if flow is not None:
                flows[(src_ip, dst_ip)] = flow

