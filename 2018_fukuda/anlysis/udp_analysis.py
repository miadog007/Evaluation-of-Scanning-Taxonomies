def udp_port_scan(udp_flows, udp_other, udp_hport_scans, udp_lport_scans):
    '''
    Check if flow is Port Scan
    Returns:
        Number of packets that is Port Scan
    '''
    flows = udp_flows
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
        avg_packet_port = flow['avg_packets_per_dst_port']
        packets = flow['num_packets']

        # Check if udp Port Scan Heavy/Light
        if dst_ports_count >= N2 and avg_packet_port > M:
            udp_hport_scans[flow_key] = {'dst_ports': dst_ports, 'dst_ports_count': dst_ports_count, 'num_packets': packets, 'avg_packet_per_port': avg_packet_port}
            udp_other_remove(flow_key, flow, udp_other)
        elif dst_ports_count >= N2 and avg_packet_port <= M:
            udp_lport_scans[flow_key] = {'dst_ports': dst_ports, 'dst_ports_count': dst_ports_count, 'num_packets': packets, 'avg_packet_per_port': avg_packet_port}
            udp_other_remove(flow_key, flow, udp_other)
        else:
            udp_other_add(flow_key, flow, udp_other, dst_ips_str, 'port_scans')

    return udp_other, udp_hport_scans, udp_lport_scans

def udp_network_scan(udp_srcs, udp_other, udp_hnetwork_scans, udp_lnetwork_scans):
    '''
    Check if flow is Network Scan
    Returns:
        Number of packets that is Network Scan
    '''
    flows = udp_srcs
    N1 = 5
    R = 50
    M = 3

    for flow_key in flows:
        flow = flows[flow_key]
        dst_ports = flow_key[1]
        dst_ips = flow['dst_ips']
        dst_ips_str = set(str(dst_ips).strip('{}').split(','))
        dst_ips_count = len(flow['dst_ips'])
        avg_packet_ip = flow['avg_packets_per_dst_ip']
        packets = flow['num_packets']
        src_ip = flow_key[0]

        # Check if udp Port Scan Heavy/Light
        if dst_ips_count >= N1 and avg_packet_ip > M:
            udp_hnetwork_scans[flow_key] = {'dst_ips': dst_ips, 'dst_ips_count': dst_ips_count, 'dst_ports': dst_ports, 'num_packets': packets, 'avg_packet_per_ip': avg_packet_ip}
            if src_ip in udp_other:
                udp_other_remove(flow_key, flow, udp_other)
        elif dst_ips_count >= N1 and avg_packet_ip <= M:
            udp_lnetwork_scans[flow_key] = {'dst_ips': dst_ips, 'dst_ips_count': dst_ips_count, 'dst_ports': dst_ports, 'num_packets': packets, 'avg_packet_per_ip': avg_packet_ip}
            if src_ip in udp_other:
                udp_other_remove(flow_key, flow, udp_other)
        else:
            udp_other_add(flow_key, flow, udp_other, dst_ips_str, 'network_scan')

    return udp_other, udp_hnetwork_scans, udp_lnetwork_scans

def one_flow(udp_one_flows, udp_other, udp_oflow_final):
    '''
    Check if flow is One Flow
    Returns:
        Number of packets that is udp One Flow
    '''
    flows = udp_one_flows
    N3 = 15

    for flow_key in flows:
        flow = flows[flow_key]    
        packets = flow['num_packets']
        src_ip = flow_key[0]
        dst_ips = flow_key[1]
        dst_port = flow_key[2]
        dst_ips_str = set(str(dst_ips).strip('{}').split(','))

        if packets >= N3:
            udp_oflow_final[flow_key] = {'dst_ips': dst_ips, 'dst_port': dst_port, 'num_packets': packets}
            if src_ip in udp_other:
                udp_other_remove(flow_key, flow, udp_other)
        else:
            udp_other_add(flow_key, flow, udp_other, dst_ips_str, 'one_flow')

    return udp_other, udp_oflow_final

def udp_backscatter(udp_backscatters, udp_backscatter_final):
    '''
    Check number of backscatter
    '''
    for flow_key in udp_backscatters:
        flow = udp_backscatters[flow_key]
        dst_ips = flow['dst_ips']
        src_port = flow['src_port']
        packets = flow['num_packets']
        udp_backscatter_final[flow_key] = {'dst_ips': dst_ips, 'src_port': src_port, 'num_packets': packets}


    return udp_backscatter_final

def udp_fragment(udp_srcs, udp_other, udp_fragment):
    flows = udp_srcs

    for flow_key in flows:
        flow = flows[flow_key]
        frag_packet = flow['frag_packets']
        src_ip = flow_key[0]
        dst_ips = flow['dst_ips']
        dst_ips_str = set(str(dst_ips).strip('{}').split(','))
        packets = flow['num_packets']
        dst_port = flow_key[1]

        if frag_packet >= 1:
            udp_fragment[flow_key] = {'dst_ips': dst_ips, 'dst_ports': dst_port, 'num_packets': packets}
            if src_ip in udp_other:
                udp_other_remove(flow_key, flow, udp_other)
        else:
            udp_other_add(flow_key, flow, udp_other, dst_ips_str, 'backscatter')

    return udp_other, udp_fragment

def small_udp(small_udps, udp_other, small_udp_final):
    '''
    Check for Small udp
    Returns:
        Number of Samll udp
    '''
    flows = small_udps
    N1 = 5
    N2 = 5
    N3 = 15

    for flow_key in flows:
        flow = flows[flow_key]
        dst_ips = flow['dst_ips']
        dst_ips_str = set(str(dst_ips).strip('{}').split(','))  
        dst_ips_count = len(flow['dst_ips'])
        dst_ports_count = len(flow['dst_ports'])
        dst_ports = flow['dst_ports']
        packets = flow['num_packets']
        src_ip = flow_key[0]

        if dst_ips_count < N1 and dst_ports_count < N2 and packets <= N3:
            small_udp_final[flow_key] = {'dst_ips': dst_ips, 'dst_ports': dst_ports, 'dst_ips_count': dst_ips_count, 'num_packets': packets}
            if src_ip in udp_other:
                udp_other_remove(flow_key, flow, udp_other)
        else:
            udp_other_add(flow_key, flow, udp_other, dst_ips_str, 'Small UDP')
    
    print('small udp analysis done')
    return udp_other, small_udp_final

def udp_other_add(flow_key, flow, udp_other, dst_ips, scan_type):
    '''
    Add to udp_other
    '''

    src_ip = flow_key[0]

    if src_ip in udp_other:
        flow = udp_other[src_ip]
        flow['scan_types_from'].add(scan_type)
        flow['dst_ips'].update(dst_ips)
        flow['num_entries'] += 1
    else:
        flow = {
            'dst_ips': set(dst_ips),
            'scan_types_from': set([scan_type]),
            'num_entries': 1
        }
        udp_other[src_ip] = flow

    return udp_other

def udp_other_remove(flow_key, flow, udp_other):
    '''
    Remove from udp_other
    '''
    src_ip = flow_key[0]

    if src_ip in udp_other:
        del udp_other[src_ip]
    else:
        return None
    
    return udp_other

def udp_remove_key_other(udp_other, udp_hport_scans, udp_lport_scans, udp_hnetwork_scans, udp_lnetwork_scans, udp_oflow_final, small_udps_final):
    keys_to_remove = {key[0] for key in [*udp_hport_scans.keys(), *udp_lport_scans.keys(), *udp_hnetwork_scans.keys(), *udp_lnetwork_scans.keys(), *udp_oflow_final.keys()]}
    
    for key in list(udp_other.keys()):
        if key in keys_to_remove:
            del udp_other[key]
    
    for key in list(udp_other.keys()):
        if key in small_udps_final:
            del udp_other[key]

    return udp_other
