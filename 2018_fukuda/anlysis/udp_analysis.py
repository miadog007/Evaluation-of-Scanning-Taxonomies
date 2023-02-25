def udp_port_scan(udp_flows):
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

        # Check if udp Port Scan Heavy/Light
        if dst_ports_count >= N2 and avg_packet_port > M:
            heavy_port_scan += 1
        elif dst_ports_count > N2 and avg_packet_port <= M:
            light_port_scan += 1

    print(f"Heavy port scans: {heavy_port_scan}")
    print(f"Light port scans: {light_port_scan}")

def udp_network_scan(udp_srcs):
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

        # Check if udp Port Scan Heavy/Light
        if dst_ips_count >= N1 and avg_packet_ip > M:
            heavy_network_scan += 1
        elif dst_ips_count > N1 and avg_packet_ip <= M:
            light_network_scan += 1

    print(f"Heavy network scans: {heavy_network_scan}")
    print(f"Light network scans: {light_network_scan}")

def one_flow(udp_one_flows):
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
            udp_one_flow += 1

    print(f"udp One Flows: {udp_one_flow}")  

def udp_backscatter(udp_backscatters):
    '''
    Check number of backscatter
    '''

    num_ips = len(udp_backscatters)
    print(f"udp backscatter connections: {num_ips}")

def small_udp(small_udps):
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
            Small_udp += 1

    print(f"Small UDP: {Small_udp}") 
