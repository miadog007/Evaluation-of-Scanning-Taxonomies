import socket
import dpkt


def icmp_single_src(packet_data, src_ip, icmp_src):
    '''
    Getting reqired information for icmp_single_src. 
    This is for Network Scan
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.icmp.ICMP):
        # Skip non-icmp packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)

    if ip_src != src_ip and ip_packet.icmp.type != 8 and ip_packet.icmp.code != 8:
        # Skip packets that don't match the specified source and destination IP addresses
        return None

    flow_key = (ip_src)

    # Check for icmp_flows that exists
    if flow_key in icmp_src:
        # Update the flow information
        flow = icmp_src[flow_key]
        flow['num_packets'] += 1
        flow['dst_ips'].add(socket.inet_ntoa(ip_packet.dst))
    else: 
        # Create new icmp_flows
        flow = {
            'dst_ips': set(),
            'num_packets': 1,
            'frag_packets': 0
        }

        icmp_src[flow_key] = flow

    # Check for fragmented packets
    if ip_packet.off & dpkt.ip.IP_OFFMASK != 0:
       flow['frag_packets'] += 1

    #  average packets per dst ip
    total_packets = flow['num_packets']
    num_dst_ips = len(flow['dst_ips'])
    if num_dst_ips > 0:
        flow['avg_packets_per_dst_ip'] = total_packets / num_dst_ips
    else:
        flow['avg_packets_per_dst_ip'] = 0

    return flow


def icmp_backscatter_check(packet_data, src_ip, icmp_backscatters):

    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.icmp.ICMP):
        # Skip non-icmp packets
        return None
    
    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)


    if (ip_packet.icmp.type == 0 and ip_packet.icmp.code == 0 or
        ip_packet.icmp.type == 3 or
        ip_packet.icmp.type == 11 and ip_packet.icmp.type == 0):
        
        flow_key = (ip_src)
        
        if flow_key in icmp_backscatters:
            # Update the flow information
            flow = icmp_backscatters[flow_key]
            flow['num_packets'] += 1
        else: 
        # Create new icmp_backscatter
            flow = {
            'num_packets': 1
        }
        icmp_backscatters[flow_key] = flow
    else:
        return None
    
    return flow  

def small_ping_check(packet_data, src_ip, small_pings):
    '''
    Getting reqired information for small_icmp. 
    This is for Small icmp
    '''
    eth_packet = dpkt.ethernet.Ethernet(packet_data)

    if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.icmp.ICMP):
        # Skip non-icmp packets
        return None

    ip_packet = eth_packet.data
    ip_src = socket.inet_ntoa(ip_packet.src)

    if ip_src != src_ip and ip_packet.data.icmp.type != 8 and ip_packet.data.icmp.code != 8:
        # Skip packets that don't match the specified information
        return None

    flow_key = (ip_src)

         # Check for icmp_flows that exists
    if flow_key in small_pings:
        # Update the flow information
        flow = small_pings[flow_key]
        flow['num_packets'] += 1
        flow['dst_ips'].add(socket.inet_ntoa(ip_packet.dst))
    else: 
        # Create new icmp_flows
        flow = {
            'dst_ips': set(),
            'num_packets': 1
        }

        small_pings[flow_key] = flow
    
    return flow