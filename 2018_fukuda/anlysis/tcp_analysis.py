def tcp_port_scan(tcp_flows, tcp_other, tcp_hport_scans, tcp_lport_scans):
    '''
    Check if flow is Port Scan
    Returns:
        Number of packets that is Port Scan
    '''
    flows = tcp_flows
    N2 = 5
    N3 = 15
    R = 50
    M = 3

    for flow_key in flows:
        flow = flows[flow_key]
        dst_ports = flow['dst_ports']
        dst_ports_count = len(flow['dst_ports'])
        dst_ips = flow_key[1]
        dst_ips_str = set(str(dst_ips).strip('{}').split(','))
        scan_percent = flow['scan_percent']
        avg_packet_port = flow['avg_packets_per_dst_port']
        packets = flow['num_packets']

        # Check if TCP Port Scan Heavy/Light
        if dst_ports_count >= N2 and scan_percent >= R and avg_packet_port > M:
            tcp_hport_scans[flow_key] = {'dst_ports': dst_ports, 'dst_ports_count': dst_ports_count, 'num_packets': packets, 'scan_percent': scan_percent, 'avg_packet_per_port': avg_packet_port}
        elif dst_ports_count >= N2 and scan_percent >= R and avg_packet_port <= M:
            tcp_lport_scans[flow_key] = {'dst_ports': dst_ports, 'dst_ports_count': dst_ports_count, 'num_packets': packets, 'scan_percent': scan_percent, 'avg_packet_per_port': avg_packet_port}
        else:
            tcp_other_add(flow_key, flow, tcp_other, dst_ips_str, 'port_scans')

    return tcp_other, tcp_hport_scans, tcp_lport_scans

def tcp_network_scan(tcp_srcs, tcp_other, tcp_hnetwork_scans, tcp_lnetwork_scans):
    '''
    Check if flow is Network Scan
    Returns:
        Number of packets that is Network Scan
    '''
    flows = tcp_srcs
    N1 = 5
    R = 50
    M = 3

    for flow_key in flows:
        flow = flows[flow_key]
        dst_ports = flow_key[1]
        dst_ips = flow['dst_ips']
        dst_ips_str = set(str(dst_ips).strip('{}').split(','))
        dst_ips_count = len(flow['dst_ips'])
        scan_percent = flow['scan_percent']
        avg_packet_ip = flow['avg_packets_per_dst_ip']
        packets = flow['num_packets']
        src_ip = flow_key[0]

        # Check if TCP Port Scan Heavy/Light
        if dst_ips_count >= N1 and scan_percent >= R and avg_packet_ip > M:
            tcp_hnetwork_scans[flow_key] = {'dst_ips': dst_ips, 'dst_ips_count': dst_ips_count, 'dst_ports': dst_ports, 'num_packets': packets, 'scan_percent': scan_percent, 'avg_packet_per_ip': avg_packet_ip}
            if src_ip in tcp_other:
                tcp_other_remove(flow_key, flow, tcp_other)
        elif dst_ips_count >= N1 and scan_percent >= R and avg_packet_ip <= M:
            tcp_lnetwork_scans[flow_key] = {'dst_ips': dst_ips, 'dst_ips_count': dst_ips_count, 'dst_ports': dst_ports, 'num_packets': packets, 'scan_percent': scan_percent, 'avg_packet_per_ip': avg_packet_ip}
            if src_ip in tcp_other:
                tcp_other_remove(flow_key, flow, tcp_other)
        else:
            tcp_other_add(flow_key, flow, tcp_other, dst_ips_str, 'network_scan')

    return tcp_other, tcp_hnetwork_scans, tcp_lnetwork_scans

def one_flow(tcp_one_flows, tcp_other, tcp_oflow_final):
    '''
    Check if flow is One Flow
    Returns:
        Number of packets that is TCP One Flow
    '''
    flows = tcp_one_flows
    N3 = 15

    for flow_key in flows:
        flow = flows[flow_key]    
        packets = flow['num_packets']
        src_ip = flow_key[0]
        dst_ips = flow_key[1]
        dst_port = flow_key[2]
        dst_ips_str = set(str(dst_ips).strip('{}').split(','))
    
        if packets >= N3:
            tcp_oflow_final[flow_key] = {'dst_ips': dst_ips, 'dst_port': dst_port, 'num_packets': packets}
            if src_ip in tcp_other:
                tcp_other_remove(flow_key, flow, tcp_other)
        else:
            tcp_other_add(flow_key, flow, tcp_other, dst_ips_str, 'one_flow')
 
    return tcp_other, tcp_oflow_final

def tcp_backscatter(tcp_backscatters, tcp_backscatter_final):
    '''
    Check number of backscatter
    '''
    for flow_key in tcp_backscatters:
        flow = tcp_backscatters[flow_key]
        dst_ips = flow['dst_ips']
        dst_port = flow['dst_port']
        packets = flow['num_packets']
        tcp_backscatter_final[flow_key] = {'dst_ips': dst_ips, 'dst_port': dst_port, 'num_packets': packets}


    return tcp_backscatter_final

def tcp_fragment(tcp_srcs, tcp_other, tcp_fragment_list):
    flows = tcp_srcs

    for flow_key in flows:
        flow = flows[flow_key]
        frag_packet = flow['frag_packets']
        src_ip = flow_key[0]
        dst_ips = flow['dst_ips']
        dst_ips_str = set(str(dst_ips).strip('{}').split(','))
        packets = flow['num_packets']
        dst_port = flow_key[1]

        if frag_packet >= 1:
            tcp_fragment_list[flow_key] = {'dst_ips': dst_ips, 'dst_ports': dst_port, 'num_packets': packets}
            if src_ip in tcp_other:
                tcp_other_remove(flow_key, flow, tcp_other)
        else:
            tcp_other_add(flow_key, flow, tcp_other, dst_ips_str, 'backscatter')

    return tcp_other, tcp_fragment_list

def small_syn(small_syns, tcp_other, small_syns_final):
    '''
    Check for Small SYN
    Returns:
        Number of Samll SYN
    '''
    flows = small_syns
    N1 = 5
    N2 = 5
    N3 = 15

    for flow_key in flows:
        flow = flows[flow_key]  
        dst_ips = flow['dst_ips']
        dst_ips_str = set(str(dst_ips).strip('{}').split(','))
        dst_ips_count = len(flow['dst_ips'])
        dst_ports = flow['dst_ports']
        dst_ports_count = len(flow['dst_ports'])
        packets = flow['num_packets']
        src_ip = flow_key[0]
    
        if dst_ips_count < N1 and dst_ports_count < N2 and packets <= N3:
            small_syns_final[flow_key] = {'dst_ips': dst_ips, 'dst_ports': dst_ports, 'dst_ips_count': dst_ips_count, 'num_packets': packets}
            if src_ip in tcp_other:
                tcp_other_remove(flow_key, flow, tcp_other)
        else:
            tcp_other_add(flow_key, flow, tcp_other, dst_ips_str, 'Small SYN')
 
    print('small SYN analysis done')
    return tcp_other, small_syns_final

def tcp_other_add(flow_key, flow, tcp_other, dst_ips, scan_type):
    '''
    Add to tcp_other
    '''

    src_ip = flow_key[0]
    packets = flow['num_packets']

    if src_ip in tcp_other:
        flow = tcp_other[src_ip]
        flow['scan_types_from'].add(scan_type)
        flow['dst_ips'].update(dst_ips)
        flow['num_entries'] += 1
    else:
        flow = {
            'dst_ips': set(dst_ips),
            'scan_types_from': set([scan_type]),
            'num_entries': 1
        }
        tcp_other[src_ip] = flow

    return tcp_other

def tcp_other_remove(flow_key, flow, tcp_other):
    '''
    Remove from tcp_other
    '''
    src_ip = flow_key[0]
    packets = flow['num_packets']

    if src_ip in tcp_other:
        del tcp_other[src_ip]
    else:
        return None
    
    return tcp_other

def tcp_remove_key_other(tcp_other, tcp_hport_scans, tcp_lport_scans, tcp_hnetwork_scans, tcp_lnetwork_scans, tcp_oflow_final, small_syns_final):
    keys_to_remove = {key[0] for key in [*tcp_hport_scans.keys(), *tcp_lport_scans.keys(), *tcp_hnetwork_scans.keys(), *tcp_lnetwork_scans.keys(), *tcp_oflow_final.keys()]}
    
    for key in list(tcp_other.keys()):
        if key in keys_to_remove:
            del tcp_other[key]
    
    for key in list(tcp_other.keys()):
        if key in small_syns_final:
            del tcp_other[key]

    return tcp_other



