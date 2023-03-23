def icmp_network_scan(icmp_srcs, icmp_other, icmp_hnetwork_scans, icmp_lnetwork_scans):
    '''
    Check if flow is Network Scan
    Returns:
        Number of packets that is Network Scan
    '''
    flows = icmp_srcs
    N1 = 5
    R = 0.50
    M = 3

    for flow_key in flows:
        flow = flows[flow_key]
        dst_ips = flow['dst_ips']
        dst_ips_str = set(str(dst_ips).strip('{}').split(','))
        dst_ips_count = len(flow['dst_ips'])
        avg_packet_ip = flow['avg_packets_per_dst_ip']
        packets = flow['num_packets']
        src_ip = flow_key[0]

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
    Check number of backscatter
    '''
    for flow_key in icmp_backscatters:
        flow = icmp_backscatters[flow_key]
        dst_ips = flow['dst_ips']
        packets = flow['num_packets']
        icmp_backscatter_final[flow_key] = {'dst_ips': dst_ips, 'num_packets': packets}


    return icmp_backscatter_final

def icmp_fragment(icmp_srcs, icmp_other, icmp_fragment):
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
                icmp_other_remove(flow_key, flow, icmp_other)
        else:
            icmp_other_add(flow_key, flow, icmp_other, dst_ips_str, 'backscatter')

    return icmp_other, icmp_fragment

def small_ping(small_pings, icmp_other, small_pings_final):
    '''
    Check for Small icmp
    Returns:
        Number of Samll icmp
    '''
    flows = small_pings
    N1 = 5
    N2 = 5
    N3 = 15

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
                icmp_other_remove(flow_key, flow, icmp_other)
        else:
            icmp_other_add(flow_key, flow, icmp_other, dst_ips_str, 'Small UDP')

    return icmp_other, small_pings_final

def icmp_other_add(flow_key, flow, icmp_other, dst_ips, scan_type):
    '''
    Add to icmp_other
    '''

    src_ip = flow_key[0]
    packets = flow['num_packets']

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

def icmp_other_remove(flow_key, flow, icmp_other):
    '''
    Remove from icmp_other
    '''
    src_ip = flow_key[0]
    packets = flow['num_packets']

    if src_ip in icmp_other:
        del icmp_other[src_ip]
    else:
        return None
    
    return icmp_other
