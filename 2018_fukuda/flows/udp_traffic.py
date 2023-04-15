import socket
import dpkt


def udp_single_flow(packet_data, src_ip, dst_ip, udp_flows):
    '''
    Getting reqired information for udp_single_flow. 
    This is for udp Port scan 
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

    # Check for udp_flows that exists
    if flow_key in udp_flows:
        # Update the flow information
        flow = udp_flows[flow_key]
        flow['num_packets'] += 1
        flow['dst_ports'].add(ip_packet.data.dport)
    else:
        # Create new udp_flows
        flow = {
            'dst_ports': set([dst_port]),
            'num_packets': 1,
        }

        udp_flows[flow_key] = flow

    #  average packets per dst port
    total_packets = flow['num_packets']
    num_dst_ports = len(flow['dst_ports'])
    if num_dst_ports > 0:
        flow['avg_packets_per_dst_port'] = total_packets / num_dst_ports
    else:
        flow['avg_packets_per_dst_port'] = 0

    return flow


def udp_single_src(packet_data, src_ip, dst_port, udp_src):
    '''
    Getting reqired information for udp_single_src. 
    This is for Network Scan
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

    # Check for udp_flows that exists
    if flow_key in udp_src:
        # Update the flow information
        flow = udp_src[flow_key]
        flow['num_packets'] += 1
        flow['dst_ips'].update(ip_dst_string)
    else:
        # Create new udp_flows
        flow = {
            'dst_ips': set(ip_dst_string),
            'num_packets': 1,
            'frag_packets': 0
        }

        udp_src[flow_key] = flow

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
    Hva kommer inn
    Hva kommer ut
    Hva gjør koden
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

    # Check for udp_flows that exists
    if flow_key in one_flows:
        # Update the flow information
        flow = one_flows[flow_key]
        flow['num_packets'] += 1
    else:
        # Create new udp_flows
        flow = {
            'num_packets': 1
        }

        one_flows[flow_key] = flow

    return flow


def udp_backscatter_check(packet_data, src_ip, udp_backscatters):

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

    if (ip_src == src_ip and
        ip_packet.data.sport == 53 or
        ip_packet.data.sport == 123 or
        ip_packet.data.sport == 137 or
            ip_packet.data.sport == 161):

        flow_key = (ip_src)

        if flow_key in udp_backscatters:
            # Update the flow information
            flow = udp_backscatters[flow_key]
            flow['num_packets'] += 1
            flow['dst_ips'].add(socket.inet_ntoa(ip_packet.dst))
            flow['src_port'].add(ip_packet.data.sport)
            flow['dst_port'].add(ip_packet.data.dport)
        else:
            # Create new udp_backscatter
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
    Getting reqired information for small_udp. 
    This is for Small UDP
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

        # Check for udp_flows that exists
        if flow_key in small_udps:
            # Update the flow information
            flow = small_udps[flow_key]
            flow['num_packets'] += 1
            flow['dst_ips'].add(socket.inet_ntoa(ip_packet.dst))
            flow['dst_ports'].add(ip_packet.data.dport)
        else:
            # Create new udp_flows
            flow = {
                'dst_ips': set(ip_dst_string),
                'dst_ports': set([port_dst]),
                'num_packets': 1
            }

            small_udps[flow_key] = flow
    else:
        return None

    return flow
