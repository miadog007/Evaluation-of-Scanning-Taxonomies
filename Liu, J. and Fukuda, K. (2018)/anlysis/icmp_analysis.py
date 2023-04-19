'''
Setting global parameters for analysing
'''
# Number of IP Destinations
N1 = 5

# Number of Destination ports
N2 = 5

# Number of Packets
N3 = 15

# Precentage
R = 50

# Packets per Destination IP/Port
M = 3


def icmp_network_scan(icmp_srcs, icmp_other, icmp_hnetwork_scans, icmp_lnetwork_scans):
    '''
    Function for finding Network scans,
    Adding to each flow:
        Key:   
            IP source
        Values:
            IP Destinations
            Number of packets
            Destination IPs count
            Avrage Number of packets per Destination IP
    Input:
        icmp_other
        icmp_network_flows dict
    Returns:
        icmp_other
        icmp_hnetwork_scans
        icmp_lnetwork_scans
    '''
    flows = icmp_srcs

    global N1, M
    N1 = 5
    M = 3

    for flow_key in flows:
        flow = flows[flow_key]
        dst_ips = flow['dst_ips']
        dst_ips_str = set(str(dst_ips).strip('{}').split(','))
        dst_ips_count = len(flow['dst_ips'])
        avg_packet_ip = flow['avg_packets_per_dst_ip']
        packets = flow['num_packets']

        # Check if icmp Port Scan Heavy/Light
        if dst_ips_count >= N1 and avg_packet_ip > M:
            icmp_hnetwork_scans[flow_key] = {'dst_ips': dst_ips, 'dst_ips_count': dst_ips_count, 'num_packets': packets, 'avg_packet_per_ip': avg_packet_ip}
        elif dst_ips_count >= N1 and avg_packet_ip <= M:
            icmp_lnetwork_scans[flow_key] = {'dst_ips': dst_ips, 'dst_ips_count': dst_ips_count, 'num_packets': packets, 'avg_packet_per_ip': avg_packet_ip}
        else:
            icmp_other_add(flow_key, flow, icmp_other, dst_ips_str, 'network_scan')


    return icmp_other, icmp_hnetwork_scans, icmp_lnetwork_scans

def icmp_backscatter(icmp_backscatters, icmp_backscatter_final):
    '''
    Function for finding Backscatter,
    Adding to each flow:
        Key:   
            IP source
        Values:
            IP Destinations
            Number of packets
    Input:
        icmp_backscatters dict
    Returns:
        icmp_backscatter_final dict
    '''
    for flow_key in icmp_backscatters:
        flow = icmp_backscatters[flow_key]
        dst_ips = flow['dst_ips']
        packets = flow['num_packets']
        icmp_backscatter_final[flow_key] = {'dst_ips': dst_ips, 'num_packets': packets}


    return icmp_backscatter_final

def icmp_fragment(icmp_srcs, icmp_other, icmp_fragment):
    '''
    Function for finding Fragment,
    Adding to each flow:
        Key:   
            IP source
        Values:
            IP Destination
            Number of packets
    Input:
    icmp_other
        icmp_port_flows
        icmp_network_flows
    Returns:
        icmp_other
        icmp_fragemnt
    ''' 
    
    flows = icmp_srcs

    for flow_key in flows:
        flow = flows[flow_key]
        frag_packet = flow['frag_packets']
        src_ip = flow_key[0]
        dst_ips = flow['dst_ips']
        dst_ips_str = set(str(dst_ips).strip('{}').split(','))
        packets = flow['num_packets']

        if frag_packet >= 1:
            icmp_fragment[flow_key] = {'dst_ips': dst_ips, 'num_packets': packets}
            if src_ip in icmp_other:
                icmp_other_remove(flow_key, icmp_other)
        else:
            icmp_other_add(flow_key, flow, icmp_other, dst_ips_str, 'backscatter')

    return icmp_other, icmp_fragment

def small_ping(small_pings, icmp_other, small_pings_final):
    '''
    Function for finding Small Ping,
    Adding to each flow:
        Key:   
            IP source
        Values:
            IP Destination
            Destination Port
            Destination IPs count
            Number of packets
    Input:
        icmp_other
        small_pings dict
    Returns:
        icmp_other
        small_pings_final dict
    '''
    flows = small_pings

    global N1, N3

    for flow_key in flows:
        flow = flows[flow_key]
        dst_ips = flow['dst_ips']
        dst_ips_str = set(str(dst_ips).strip('{}').split(','))   
        dst_ips_count = len(flow['dst_ips'])
        packets = flow['num_packets']
        src_ip = flow_key[0]
    
        if dst_ips_count < N1 and packets <= N3:
            small_pings_final[flow_key] = {'dst_ips': dst_ips, 'dst_ips_count': dst_ips_count, 'num_packets': packets}
            if src_ip in icmp_other:
                icmp_other_remove(flow_key, icmp_other)
        else:
            icmp_other_add(flow_key, flow, icmp_other, dst_ips_str, 'Small icmp')

    return icmp_other, small_pings_final

def icmp_other_add(flow_key, flow, icmp_other, dst_ips, scan_type):
    '''
    Add to icmp_other
    '''

    src_ip = flow_key[0]

    if src_ip in icmp_other:
        flow = icmp_other[src_ip]
        flow['scan_types_from'].add(scan_type)
        flow['dst_ips'].update(dst_ips)
        flow['num_entries'] += 1
    else:
        flow = {
            'dst_ips': set(dst_ips),
            'scan_types_from': set([scan_type]),
            'num_entries': 1
        }
        icmp_other[src_ip] = flow

    return icmp_other

def icmp_other_remove(flow_key, icmp_other):
    '''
    Remove from icmp_other
    '''
    src_ip = flow_key[0]

    if src_ip in icmp_other:
        del icmp_other[src_ip]
    else:
        return None
    
    return icmp_other

def icmp_remove_key_other(icmp_other, icmp_hnetwork_scans, icmp_lnetwork_scans, small_pings_final):
    '''
    Removes all Source IPs categories in an anomaly
    
    Input:
        All icmp dicts
    Output:
        icmp_other dict
    '''
    
    keys_to_remove = {key[0] for key in [*icmp_hnetwork_scans.keys(), *icmp_lnetwork_scans.keys()]}
    
    for key in list(icmp_other.keys()):
        if key in keys_to_remove:
            del icmp_other[key]
    
    for key in list(icmp_other.keys()):
        if key in small_pings_final:
            del icmp_other[key]

    return icmp_other