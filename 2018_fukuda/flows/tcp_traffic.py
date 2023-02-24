import socket
import dpkt


def tcp_single_flow(packet_data, src_ip, dst_ip, tcp_flows):
    '''
    Getting reqired information for tcp_single_flow. 
    This is for TCP Port scan, TCP One flow, TCP Backscatter, IP fragment and Other TCP
    '''
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

    # Check for tcp_flows that exists
    if flow_key in tcp_flows:
        # Update the flow information
        flow = tcp_flows[flow_key]
        flow['num_packets'] += 1
        flow['dst_ports'].add(ip_packet.data.dport)
    else: 
        # Create new tcp_flows
        flow = {
            'src_ip': ip_src,
            'dst_ip': ip_dst,
            'dst_ports': set(),
            'num_packets': 1,
            'scan_packets': 0,
            'syn_packets': 0,
            'frag_packets': 0
        }

        tcp_flows[flow_key] = flow

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

        # Calculate percentages
    total_packets = flow['num_packets']
    if total_packets > 0:
        flow['scan_percent'] = 100 * flow['scan_packets'] / total_packets
        flow['syn_percent'] = 100 * flow['syn_packets'] / total_packets
        flow['frag_percent'] = 100 * flow['frag_packets'] / total_packets
    else:
        flow['scan_percent'] = 0
        flow['syn_percent'] = 0
        flow['frag_percent'] = 0
    
    #  average packets per dst port
    num_dst_ports = len(flow['dst_ports'])
    if num_dst_ports > 0:
        flow['avg_packets_per_dst_port'] = total_packets / num_dst_ports
    else:
        flow['avg_packets_per_dst_port'] = 0

    return flow
    

def tcp_single_src(packet_data, src_ip, dst_port, tcp_src):
    '''
    Getting reqired information for tcp_single_src. 
    This is for Network Scan
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.tcp.TCP):
        # Skip non-TCP packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)
    port_dst = ip_packet.data.dport

    if ip_src != src_ip or port_dst != dst_port:
        # Skip packets that don't match the specified source and destination IP addresses
        return None

    flow_key = (ip_src, port_dst)

        # Check for tcp_flows that exists
    if flow_key in tcp_src:
        # Update the flow information
        flow = tcp_src[flow_key]
        flow['num_packets'] += 1
        flow['dst_ips'].add(socket.inet_ntoa(ip_packet.dst))
    else: 
        # Create new tcp_flows
        flow = {
            'src_ip': ip_src,
            'dst_port': port_dst,
            'dst_ips': set(),
            'num_packets': 1,
            'scan_packets': 0,
            'syn_packets': 0,
            'frag_packets': 0
        }

        tcp_src[flow_key] = flow

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

        # Calculate percentages
    total_packets = flow['num_packets']
    if total_packets > 0:
        flow['scan_percent'] = 100 * flow['scan_packets'] / total_packets
        flow['syn_percent'] = 100 * flow['syn_packets'] / total_packets
    else:
        flow['scan_percent'] = 0
        flow['syn_percent'] = 0
    
    #  average packets per dst ip
    num_dst_ips = len(flow['dst_ips'])
    if num_dst_ips > 0:
        flow['avg_packets_per_dst_ip'] = total_packets / num_dst_ips
    else:
        flow['avg_packets_per_dst_ip'] = 0

    return flow

#def small_syn():

