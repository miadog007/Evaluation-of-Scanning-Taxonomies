import socket
import dpkt


def udp_single_flow(packet_data, src_ip, dst_ip, udp_port_flows):
    '''
    Function for finding potenial Port scans,
    Adding to each flow:
        Key:   
            IP source
            IP Destination
        Values:
            Destination Ports
            Number of packets
            Avrage Number of packets per Destination Port
            Fragment Packets
    Input:
        Packet from Packet capture
        udp_port_flows dicts
    Returns:
        flow to udp_port_flows
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.udp.UDP):
        # Skip non-udp packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)
    ip_dst = socket.inet_ntoa(ip_packet.dst)
    dst_port = ip_packet.data.dport
    if ip_src != src_ip or ip_dst != dst_ip:
        # Skip packets that don't match the specified source and destination IP addresses
        return None

    flow_key = (ip_src, ip_dst)

    # Check for udp_port_flows that exists
    if flow_key in udp_port_flows:
        # Update the flow information
        flow = udp_port_flows[flow_key]
        flow['num_packets'] += 1
        flow['dst_ports'].add(ip_packet.data.dport)
    else:
        # Create new udp_port_flows
        flow = {
            'dst_ports': set([dst_port]),
            'num_packets': 1,
        }

        udp_port_flows[flow_key] = flow

    #  average packets per dst port
    total_packets = flow['num_packets']
    num_dst_ports = len(flow['dst_ports'])
    if num_dst_ports > 0:
        flow['avg_packets_per_dst_port'] = total_packets / num_dst_ports
    else:
        flow['avg_packets_per_dst_port'] = 0

    return flow


def udp_single_src(packet_data, src_ip, dst_port, udp_network_flows):
    '''
    Function for finding potenial Network scans,
    Adding to each flow:
        Key:   
            IP source
            Destination Port
        Values:
            IP destinations
            Number of packets
            Avrage Number of packets per Destination IP
            Fragment Packets
    Input:
        Packet from Packet capture
        udp_network_flows dicts
    Returns:
        flow to udp_network_flows
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.udp.UDP):
        # Skip non-udp packets
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

    # Check for udp_network_flows that exists
    if flow_key in udp_network_flows:
        # Update the flow information
        flow = udp_network_flows[flow_key]
        flow['num_packets'] += 1
        flow['dst_ips'].update(ip_dst_string)
    else:
        # Create new udp_network_flows
        flow = {
            'dst_ips': set(ip_dst_string),
            'num_packets': 1,
            'frag_packets': 0
        }

        udp_network_flows[flow_key] = flow

    # Check for fragmented packets
    if (ip_packet.off & dpkt.ip.IP_MF) != 0 or (ip_packet.off & dpkt.ip.IP_OFFMASK) != 0:
        flow['frag_packets'] += 1

    #  average packets per dst ip
    total_packets = flow['num_packets']
    num_dst_ips = len(flow['dst_ips'])
    if num_dst_ips > 0:
        flow['avg_packets_per_dst_ip'] = total_packets / num_dst_ips
    else:
        flow['avg_packets_per_dst_ip'] = 0

    return flow


def udp_one_flow(packet_data, src_ip, dst_ip, dst_port, one_flows):
    '''
    Function for finding potenial UDP One flow,
    Adding to each flow:
        Key:   
            IP source
            IP destinations
            Destination Port
        Values:
            Number of packets
    Input:
        Packet from Packet capture
        udp_one_flows dicts
    Returns:
        flow to udp_one_flows
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.udp.UDP):
        # Skip non-udp packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)
    ip_dst = socket.inet_ntoa(ip_packet.dst)
    port_dst = ip_packet.data.dport

    if ip_src != src_ip or ip_dst != dst_ip or port_dst != dst_port:
        # Skip packets that don't match the specified source and destination IP addresses
        return None

    flow_key = (ip_src, ip_dst, port_dst)

    # Check for one_flows that exists
    if flow_key in one_flows:
        # Update the flow information
        flow = one_flows[flow_key]
        flow['num_packets'] += 1
    else:
        # Create new one_flows
        flow = {
            'num_packets': 1
        }

        one_flows[flow_key] = flow

    return flow


def udp_backscatter_check(packet_data, src_ip, udp_backscatters):
    '''
    Function for finding potenial UDP backscatter,
    Adding to each flow:
        Key:   
            IP source
        Values:
            Destination IPs
            Destination Ports
            Source Ports
            Number of packets
    Input:
        Packet from Packet capture
        udp_backscatter dict
    Returns:
        flow to udp_backscatter flows
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.udp.UDP):
        # Skip non-udp packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)
    ip_dst = socket.inet_ntoa(ip_packet.dst)
    ip_dst_string = set(str(ip_dst).strip('{}').split(','))
    port_src = ip_packet.data.sport
    port_dst = ip_packet.data.dport

    '''
    Find backscatter packets for TCP
    (Source Port: 53 or 123 or 137 or 161)
    '''
    # If not backscatter packet, return None
    if (ip_src == src_ip and
        ip_packet.data.sport == 53 or
        ip_packet.data.sport == 123 or
        ip_packet.data.sport == 137 or
            ip_packet.data.sport == 161):

        flow_key = (ip_src)

        if flow_key in udp_backscatters:
            # Update exsisting udp_backscatter flow information
            flow = udp_backscatters[flow_key]
            flow['num_packets'] += 1
            flow['dst_ips'].add(socket.inet_ntoa(ip_packet.dst))
            flow['src_port'].add(ip_packet.data.sport)
            flow['dst_port'].add(ip_packet.data.dport)
        else:
            # Create new udp_backscatter flow
            flow = {
                'dst_ips': set(ip_dst_string),
                'src_port': set([port_src]),
                'dst_port': set([port_dst]),
                'num_packets': 1
            }
        udp_backscatters[flow_key] = flow
    else:
        return None

    return flow


def small_udp_check(packet_data, src_ip, small_udps):
    '''
    Function for finding potenial Small UDPs,
    Adding to each flow:
        Key:   
            IP source
        Values:
            Destination IPs
            Destination ports
            Number of packets
    Input:
        Packet from Packet capture
        small_udps dict
    Returns:
        flow to small_udps flows
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.udp.UDP):
        # Skip non-udp packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)
    ip_dst = socket.inet_ntoa(ip_packet.dst)
    ip_dst_string = set(str(ip_dst).strip('{}').split(','))
    port_dst = ip_packet.data.dport
    if ip_src == src_ip:

        flow_key = (ip_src)

        # Check for small_udps flows that exists
        if flow_key in small_udps:
            # Update the flow information
            flow = small_udps[flow_key]
            flow['num_packets'] += 1
            flow['dst_ips'].add(socket.inet_ntoa(ip_packet.dst))
            flow['dst_ports'].add(ip_packet.data.dport)
        else:
            # Create new small_udps flow
            flow = {
                'dst_ips': set(ip_dst_string),
                'dst_ports': set([port_dst]),
                'num_packets': 1
            }

            small_udps[flow_key] = flow
    else:
        return None

    return flow
