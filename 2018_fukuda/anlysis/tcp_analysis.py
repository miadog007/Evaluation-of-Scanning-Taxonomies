def tcp_port_scan(tcp_flows, tcp_other):
    '''
    Check if flow is Port Scan
    Returns:
        Number of packets that is Port Scan
    '''
    flows = tcp_flows
    heavy_port_scan = 0
    light_port_scan = 0
    N2 = 5
    N3 = 15
    R = 0.50
    M = 3

    for flow_key in flows:
        flow = flows[flow_key]
        dst_ports_count = len(flow['dst_ports'])
        scan_percent = flow['scan_percent']
        avg_packet_port = flow['avg_packets_per_dst_port']
        packets = flow['num_packets']

        # Check if TCP Port Scan Heavy/Light
        if dst_ports_count >= N2 and scan_percent >= R and avg_packet_port > M:
            heavy_port_scan += packets
        elif dst_ports_count > N2 and scan_percent >= R and avg_packet_port <= M:
            light_port_scan += packets
        else:
            tcp_other_add(flow_key, flow, tcp_other)

    print(f"Heavy port scans: {heavy_port_scan}")
    print(f"Light port scans: {light_port_scan}")
    return(tcp_other)

def tcp_network_scan(tcp_srcs, tcp_other):
    '''
    Check if flow is Network Scan
    Returns:
        Number of packets that is Network Scan
    '''
    flows = tcp_srcs
    heavy_network_scan = 0
    light_network_scan = 0
    N1 = 5
    R = 0.50
    M = 3

    for flow_key in flows:
        flow = flows[flow_key]
        dst_ips_count = len(flow['dst_ips'])
        scan_percent = flow['scan_percent']
        avg_packet_ip = flow['avg_packets_per_dst_ip']
        packets = flow['num_packets']
        src_ip = flow_key[0]

        # Check if TCP Port Scan Heavy/Light
        if dst_ips_count >= N1 and scan_percent >= R and avg_packet_ip > M:
            heavy_network_scan += packets
            if src_ip in tcp_other:
                tcp_other_remove(flow_key, flow, tcp_other)
        elif dst_ips_count > N1 and scan_percent >= R and avg_packet_ip <= M:
            light_network_scan += packets
            if src_ip in tcp_other:
                tcp_other_remove(flow_key, flow, tcp_other)
        else:
            tcp_other_add(flow_key, flow, tcp_other)

    print(f"Heavy network scans: {heavy_network_scan}")
    print(f"Light network scans: {light_network_scan}")
    return tcp_other

def one_flow(tcp_one_flows, tcp_other):
    '''
    Check if flow is One Flow
    Returns:
        Number of packets that is TCP One Flow
    '''
    flows = tcp_one_flows
    tcp_one_flow = 0
    N3 = 15

    for flow_key in flows:
        flow = flows[flow_key]    
        packets = flow['num_packets']
        src_ip = flow_key[0]
    
        if packets >= N3:
            tcp_one_flow += packets
            if src_ip in tcp_other:
                tcp_other_remove(flow_key, flow, tcp_other)
        else:
            tcp_other_add(flow_key, flow, tcp_other)

    print(f"TCP One Flows: {tcp_one_flow}")  
    return tcp_other

def tcp_backscatter(tcp_backscatters):
    '''
    Check number of backscatter
    '''
    total_packets = 0
    for flow_key in tcp_backscatters:
        flow = tcp_backscatters[flow_key]
        total_packets += flow['num_packets']


    print(f"TCP backscatter connections: {total_packets}")

def tcp_fragment(tcp_srcs, tcp_other):
    flows = tcp_srcs
    frag_connections = 0

    for flow_key in flows:
        flow = flows[flow_key]
        frag_packet = flow['frag_packets']
        src_ip = flow_key[0]
        packets = flow['num_packets']

        if frag_packet >= 1:
            frag_connections += packets
            if src_ip in tcp_other:
                tcp_other_remove(flow_key, flow, tcp_other)
        else:
            tcp_other_add(flow_key, flow, tcp_other)

    print(f"IP Fragement: {frag_connections}")
    return tcp_other

def small_syn(small_syns, tcp_other):
    '''
    Check for Small SYN
    Returns:
        Number of Samll SYN
    '''
    flows = small_syns
    Small_SYN = 0
    N1 = 5
    N2 = 5
    N3 = 15

    for flow_key in flows:
        flow = flows[flow_key]  
        dst_ips_count = len(flow['dst_ips'])
        dst_ports_count = len(flow['dst_ports'])
        packets = flow['num_packets']
        src_ip = flow_key[0]
    
        if dst_ips_count < N1 and dst_ports_count < N2 and packets <= N3:
            Small_SYN += packets
            if src_ip in tcp_other:
                tcp_other_remove(flow_key, flow, tcp_other)
        else:
            tcp_other_add(flow_key, flow, tcp_other)

    print(f"Small SYN: {Small_SYN}") 
    return tcp_other

def tcp_other_add(flow_key, flow, tcp_other):
    '''
    Add to tcp_other
    '''

    src_ip = flow_key[0]
    packets = flow['num_packets']

    if src_ip in tcp_other:
        tcp_other[src_ip] += packets
    else:
        tcp_other[src_ip] = packets

    return tcp_other

def tcp_other_remove(flow_key, flow, tcp_other):
    '''
    Remove from tcp_other
    '''
    src_ip = flow_key[0]
    packets = flow['num_packets']

    if src_ip in tcp_other:
        tcp_other[src_ip] -= packets
        if tcp_other[src_ip] <= 0:
            del tcp_other[src_ip]
    else:
        return None
    
    return tcp_other





