import socket
import dpkt


def tcp_single_flow(packet_data, src_ip, dst_ip, tcp_flows):
    '''
    Getting reqired information for tcp_single_flow. 
    This is for TCP Port scan
        Returns:
        List of possible port scans ready for analyzing
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.tcp.TCP):
        # Skip non-TCP packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)
    ip_dst = socket.inet_ntoa(ip_packet.dst)
    dst_port = ip_packet.data.dport
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
            'dst_ports': set([dst_port]),
            'num_packets': 1,
            'scan_packets': 0,
        }

        tcp_flows[flow_key] = flow

    # Update flags counters
    if (ip_src == src_ip and 
        ((ip_packet.data.flags & dpkt.tcp.TH_SYN and
        not ip_packet.data.flags & 
            (dpkt.tcp.TH_ACK | dpkt.tcp.TH_RST | dpkt.tcp.TH_FIN | dpkt.tcp.TH_PUSH | dpkt.tcp.TH_URG)) or 
        (ip_packet.data.flags & dpkt.tcp.TH_FIN and 
        not ip_packet.data.flags & 
            (dpkt.tcp.TH_SYN | dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH | dpkt.tcp.TH_URG)) or 
        (ip_packet.data.flags & dpkt.tcp.TH_FIN and ip_packet.data.flags & dpkt.tcp.TH_ACK and
        not ip_packet.data.flags & 
            (dpkt.tcp.TH_SYN | dpkt.tcp.TH_URG | dpkt.tcp.TH_RST | dpkt.tcp.TH_PUSH)) or
        ((ip_packet.data.flags & dpkt.tcp.TH_FIN == 0) and 
        (ip_packet.data.flags & dpkt.tcp.TH_SYN == 0) and 
        (ip_packet.data.flags & dpkt.tcp.TH_RST == 0) and 
        (ip_packet.data.flags & dpkt.tcp.TH_PUSH == 0) and 
        (ip_packet.data.flags & dpkt.tcp.TH_ACK == 0) and 
        (ip_packet.data.flags & dpkt.tcp.TH_URG == 0)))):
        flow['scan_packets'] += 1

        # Calculate percentages
    total_packets = flow['num_packets']
    if total_packets > 0:
        flow['scan_percent'] = flow['scan_packets'] / total_packets * 100
    else:
        flow['scan_percent'] = 0
    
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
        Returns:
        List of possible network scans ready for analyzing
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.tcp.TCP):
        # Skip non-TCP packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)
    ip_dst = socket.inet_ntoa(ip_packet.dst)
    ip_dst_string = set(str(ip_dst).strip('{}').split(','))
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
        flow['dst_ips'].update(ip_dst_string)
    else: 
        # Create new tcp_flows
        flow = {
            'dst_ips': set(ip_dst_string),
            'num_packets': 1,
            'scan_packets': 0,
            'frag_packets': 0
        }

        tcp_src[flow_key] = flow

    # Update flags counters
    if (ip_src == src_ip and 
        ((ip_packet.data.flags & dpkt.tcp.TH_SYN and
        not ip_packet.data.flags & 
            (dpkt.tcp.TH_ACK | dpkt.tcp.TH_RST | dpkt.tcp.TH_FIN | dpkt.tcp.TH_PUSH | dpkt.tcp.TH_URG)) or 
        (ip_packet.data.flags & dpkt.tcp.TH_FIN and 
        not ip_packet.data.flags & 
            (dpkt.tcp.TH_SYN | dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH | dpkt.tcp.TH_URG)) or 
        (ip_packet.data.flags & dpkt.tcp.TH_FIN and ip_packet.data.flags & dpkt.tcp.TH_ACK and
        not ip_packet.data.flags & 
            (dpkt.tcp.TH_SYN | dpkt.tcp.TH_URG | dpkt.tcp.TH_RST | dpkt.tcp.TH_PUSH)) or
        ((ip_packet.data.flags & dpkt.tcp.TH_FIN == 0) and 
        (ip_packet.data.flags & dpkt.tcp.TH_SYN == 0) and 
        (ip_packet.data.flags & dpkt.tcp.TH_RST == 0) and 
        (ip_packet.data.flags & dpkt.tcp.TH_PUSH == 0) and 
        (ip_packet.data.flags & dpkt.tcp.TH_ACK == 0) and 
        (ip_packet.data.flags & dpkt.tcp.TH_URG == 0)))):
        flow['scan_packets'] += 1


    # Check for fragmented packets
    if (ip_packet.off & dpkt.ip.IP_MF) != 0 or (ip_packet.off & dpkt.ip.IP_OFFMASK) != 0:
       flow['frag_packets'] += 1
    
    # Calculate percentages
    total_packets = flow['num_packets']
    if total_packets > 0:
        flow['scan_percent'] = flow['scan_packets'] / total_packets * 100
    else:
        flow['scan_percent'] = 0
    
    #  average packets per dst ip
    num_dst_ips = len(flow['dst_ips'])
    if num_dst_ips > 0:
        flow['avg_packets_per_dst_ip'] = total_packets / num_dst_ips
    else:
        flow['avg_packets_per_dst_ip'] = 0
    
    return flow

def tcp_one_flow(packet_data, src_ip, dst_ip, dst_port, one_flows):
    '''
    Getting reqired information for tcp_one_flow. 
    This is for One flow
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.tcp.TCP):
        # Skip non-TCP packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)
    ip_dst = socket.inet_ntoa(ip_packet.dst)
    port_dst = ip_packet.data.dport

    if ip_src != src_ip or ip_dst != dst_ip or port_dst != dst_port:
        # Skip packets that don't match the specified source and destination IP addresses
        return None

    flow_key = (ip_src, ip_dst, port_dst)

    # Check for tcp_flows that exists
    if flow_key in one_flows:
        # Update the flow information
        flow = one_flows[flow_key]
        flow['num_packets'] += 1
    else: 
        # Create new tcp_flows
        flow = {
            'num_packets': 1
        }

        one_flows[flow_key] = flow
    
    return flow

def tcp_backscatter_check(packet_data, src_ip, tcp_backscatters):

    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.tcp.TCP):
        # Skip non-TCP packets
        return None
    
    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)
    ip_dst = socket.inet_ntoa(ip_packet.dst)
    ip_dst_string = set(str(ip_dst).strip('{}').split(','))
    port_dst = ip_packet.data.dport

    if (ip_src == src_ip and 
        ((ip_packet.data.flags & dpkt.tcp.TH_SYN and ip_packet.data.flags & dpkt.tcp.TH_ACK and
        not ip_packet.data.flags & 
            (dpkt.tcp.TH_RST | dpkt.tcp.TH_FIN | dpkt.tcp.TH_PUSH | dpkt.tcp.TH_URG)) or 
        (ip_packet.data.flags & dpkt.tcp.TH_ACK and 
        not ip_packet.data.flags & 
            (dpkt.tcp.TH_SYN | dpkt.tcp.TH_RST | dpkt.tcp.TH_FIN | dpkt.tcp.TH_PUSH | dpkt.tcp.TH_URG)) or 
        (ip_packet.data.flags & dpkt.tcp.TH_RST and 
        not ip_packet.data.flags & 
            (dpkt.tcp.TH_ACK | dpkt.tcp.TH_SYN | dpkt.tcp.TH_URG | dpkt.tcp.TH_FIN | dpkt.tcp.TH_PUSH))
        or 
        (ip_packet.data.flags & dpkt.tcp.TH_RST and ip_packet.data.flags & dpkt.tcp.TH_ACK and 
        not ip_packet.data.flags & 
            (dpkt.tcp.TH_SYN | dpkt.tcp.TH_URG | dpkt.tcp.TH_FIN | dpkt.tcp.TH_PUSH)))):

        
        flow_key = (ip_src)
        
        if flow_key in tcp_backscatters:
            # Update the flow information
            flow = tcp_backscatters[flow_key]
            flow['num_packets'] += 1
            flow['dst_ips'].add(socket.inet_ntoa(ip_packet.dst))
            flow['dst_port'].add(port_dst)
        else: 
        # Create new tcp_backscatter
            flow = {
            'dst_ips': set(ip_dst_string),
            'dst_port': set([port_dst]),
            'num_packets': 1
        }
        tcp_backscatters[flow_key] = flow
    else:
        return None
    
    return flow  

def small_syn_check(packet_data, src_ip, small_syns):
    '''
    Getting reqired information for small_syn. 
    This is for Small SYN
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.tcp.TCP):
        # Skip non-TCP packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)
    ip_dst = socket.inet_ntoa(ip_packet.dst)
    ip_dst_string = set(str(ip_dst).strip('{}').split(','))
    port_dst = ip_packet.data.dport
    if ip_src != src_ip:
        return None

    if ip_packet.data.flags & dpkt.tcp.TH_SYN and not ip_packet.data.flags & (dpkt.tcp.TH_ACK | dpkt.tcp.TH_RST | dpkt.tcp.TH_FIN | dpkt.tcp.TH_PUSH | dpkt.tcp.TH_URG):
        # Skip packets that don't match the specified information

        flow_key = (ip_src)

            # Check for tcp_flows that exists
        if flow_key in small_syns:
            # Update the flow information
            flow = small_syns[flow_key]
            flow['num_packets'] += 1
            flow['dst_ips'].add(socket.inet_ntoa(ip_packet.dst))
            flow['dst_ports'].add(ip_packet.data.dport)
        else: 
            # Create new tcp_flows
            flow = {
                'dst_ips': set(ip_dst_string),
                'dst_ports': set([port_dst]),
                'num_packets': 1
            }

            small_syns[flow_key] = flow
    else:
        return None
    
    return flow