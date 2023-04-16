import socket
import dpkt


def icmp_single_src(packet_data, src_ip, icmp_network_flows):
    '''
    Function for finding potenial Network scans,
    Adding to each flow:
        Key:   
            IP source
        Values:
            IP destinations
            Number of packets
            Avrage Number of packets per Destination IP
            Fragment packets
    Input:
        Packet from Packet captuure
        icmp_network_flows dicts
    Returns:
        flow to icmp_network_flows
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.icmp.ICMP):
        # Skip non-icmp packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)
    ip_dst = socket.inet_ntoa(ip_packet.dst)
    ip_dst_string = set(str(ip_dst).strip('{}').split(','))
    
    # Skip packets that don't match the specified source and destination IP addresses
    if ip_src != src_ip and ip_packet.icmp.type != 8 and ip_packet.icmp.code != 8:
        return None

    flow_key = (ip_src)

    # Check for icmp_network_flows that exists
    if flow_key in icmp_network_flows:
        # Update the flow information
        flow = icmp_network_flows[flow_key]
        flow['num_packets'] += 1
        flow['dst_ips'].add(socket.inet_ntoa(ip_packet.dst))
    else:
        # Create new icmp_networ_flows
        flow = {
            'dst_ips': set(ip_dst_string),
            'num_packets': 1,
            'frag_packets': 0
        }

        icmp_network_flows[flow_key] = flow

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


def icmp_backscatter_check(packet_data, icmp_backscatters):
    '''
    Function for finding potenial ICMP backscatter,
    Adding to each flow:
        Key:   
            IP source
        Values:
            Destination IPs
            Number of packets
    Input:
        Packet from Packet capture
        icmp_backscatter dict
    Returns:
        flow to icmp_backscatter flows
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.icmp.ICMP):
        # Skip non-icmp packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)
    ip_dst = socket.inet_ntoa(ip_packet.dst)
    ip_dst_string = set(str(ip_dst).strip('{}').split(','))

    '''
    Find backscatter packets for TCP
    (Type,Code: 0,0 or 3, or 11,0)
    '''
    # If not backscatter packet, return None
    if (ip_packet.icmp.type == 0 and ip_packet.icmp.code == 0 or
        ip_packet.icmp.type == 3 or
            ip_packet.icmp.type == 11 and ip_packet.icmp.type == 0):

        flow_key = (ip_src)

        if flow_key in icmp_backscatters:
            # Update exsisting icmp_backscatter flow information
            flow = icmp_backscatters[flow_key]
            flow['num_packets'] += 1
            flow['dst_ips'].add(socket.inet_ntoa(ip_packet.dst))
        else:
            # Create new icmp_backscatter flow
            flow = {
                'dst_ips': set(ip_dst_string),
                'num_packets': 1
            }
        icmp_backscatters[flow_key] = flow
    else:
        return None

    return flow


def small_ping_check(packet_data, small_pings):
    '''
    Function for finding potenial Small Pings,
    Adding to each flow:
        Key:   
            IP source
        Values:
            Destination IPs
            Number of packets
    Input:
        Packet from Packet capture
        small_pings dict
    Returns:
        flow to small_pings flows
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.icmp.ICMP):
        # Skip non-icmp packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)
    ip_dst = socket.inet_ntoa(ip_packet.dst)
    ip_dst_string = set(str(ip_dst).strip('{}').split(','))

    # Skip packets that don't match the specified information
    if ip_packet.icmp.type == 8 and ip_packet.icmp.code == 0:

        flow_key = (ip_src)

        # Check for small_pings flows that exists
        if flow_key in small_pings:
            # Update the flow information
            flow = small_pings[flow_key]
            flow['num_packets'] += 1
            flow['dst_ips'].add(socket.inet_ntoa(ip_packet.dst))
        else:
            # Create new small_pings flow
            flow = {
                'dst_ips': set(ip_dst_string),
                'num_packets': 1
            }

            small_pings[flow_key] = flow
    else:
        return None

    return flow
