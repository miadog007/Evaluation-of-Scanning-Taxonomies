def udp_port_scan(udp_flows, udp_other):
    '''
    Check if flow is Port Scan
    Returns:
        Number of packets that is Port Scan
    '''
    flows = udp_flows
    heavy_port_scan = 0
    light_port_scan = 0
    N2 = 5
    N3 = 15
    R = 0.50
    M = 3

    for flow_key in flows:
        flow = flows[flow_key]
        dst_ports_count = len(flow['dst_ports'])
        avg_packet_port = flow['avg_packets_per_dst_port']
        packets = flow['num_packets']

        # Check if udp Port Scan Heavy/Light
        if dst_ports_count >= N2 and avg_packet_port > M:
            heavy_port_scan += packets
        elif dst_ports_count > N2 and avg_packet_port <= M:
            light_port_scan += packets
        else:
            udp_other_add(flow_key, flow, udp_other)

    print(f"Heavy port scans: {heavy_port_scan}")
    print(f"Light port scans: {light_port_scan}")
    return udp_other

def udp_network_scan(udp_srcs, udp_other):
    '''
    Check if flow is Network Scan
    Returns:
        Number of packets that is Network Scan
    '''
    flows = udp_srcs
    heavy_network_scan = 0
    light_network_scan = 0
    N1 = 5
    R = 0.50
    M = 3

    for flow_key in flows:
        flow = flows[flow_key]
        dst_ips_count = len(flow['dst_ips'])
        avg_packet_ip = flow['avg_packets_per_dst_ip']
        packets = flow['num_packets']

        # Check if udp Port Scan Heavy/Light
        if dst_ips_count >= N1 and avg_packet_ip > M:
            heavy_network_scan += packets
            udp_other_remove(flow_key, flow, udp_other)
        elif dst_ips_count > N1 and avg_packet_ip <= M:
            light_network_scan += packets
            udp_other_remove(flow_key, flow, udp_other)
        else:
            udp_other_add(flow_key, flow, udp_other)

    print(f"Heavy network scans: {heavy_network_scan}")
    print(f"Light network scans: {light_network_scan}")
    return udp_other

def one_flow(udp_one_flows, udp_other):
    '''
    Check if flow is One Flow
    Returns:
        Number of packets that is udp One Flow
    '''
    flows = udp_one_flows
    udp_one_flow = 0
    N3 = 15

    for flow_key in flows:
        flow = flows[flow_key]    
        packets = flow['num_packets']
    
        if packets >= N3:
            udp_one_flow += packets
            udp_other_remove(flow_key, flow, udp_other)
        else:
            udp_other_add(flow_key, flow, udp_other)

    print(f"udp One Flows: {udp_one_flow}")
    return udp_other

def udp_backscatter(tcp_backscatters):
    '''
    Check number of backscatter
    '''
    total_packets = 0
    for flow_key in tcp_backscatters:
        flow = tcp_backscatters[flow_key]
        total_packets += flow['num_packets']


    print(f"UDP backscatter connections: {total_packets}")

def udp_fragment(udp_srcs, udp_other):
    flows = udp_srcs
    frag_connections = 0

    for flow_key in flows:
        flow = flows[flow_key]
        frag_packet = flow['frag_packets']

        if frag_packet >= 1:
            frag_connections += frag_packet
            udp_other_remove(flow_key, flow, udp_other)
        else:
            udp_other_add(flow_key, flow, udp_other)

    print(f"IP Fragement: {frag_connections}")
    return udp_other

def small_udp(small_udps, udp_other):
    '''
    Check for Small udp
    Returns:
        Number of Samll udp
    '''
    flows = small_udps
    Small_udp = 0
    N1 = 5
    N2 = 5
    N3 = 15

    for flow_key in flows:
        flow = flows[flow_key]  
        dst_ips_count = len(flow['dst_ips'])
        dst_ports_count = len(flow['dst_ports'])
        packets = flow['num_packets']
    
        if dst_ips_count < N1 and dst_ports_count < N2 and packets <= N3:
            Small_udp += packets
            udp_other_remove(flow_key, flow, udp_other)
        else:
            udp_other_add(flow_key, flow, udp_other)

    print(f"Small UDP: {Small_udp}")
    return udp_other

def udp_other_add(flow_key, flow, udp_other):
    '''
    Add to udp_other
    '''

    src_ip = flow_key[0]
    packets = flow['num_packets']

    if src_ip in udp_other:
        udp_other[src_ip] += packets
    else:
        udp_other[src_ip] = packets

    return udp_other

def udp_other_remove(flow_key, flow, udp_other):
    '''
    Remove from udp_other
    '''
    src_ip = flow_key[0]
    packets = flow['num_packets']

    if src_ip in udp_other:
        udp_other[src_ip] -= packets
        if udp_other[src_ip] <= 0:
            del udp_other[src_ip]
    else:
        return None
    
    return udp_other
