def tcp_port_scan(tcp_flows):
    '''
    Check if flow is Port Scan
    Returns:
        Number of packets that is Port Scan
    '''
    flows = tcp_flows
    heavy_port_scan = 0
    light_port_scan = 0
    tcp_one_flow = 0
    N2 = 5
    N3 = 15
    R = 0.50
    M = 3

    for flow_key in flows:
        flow = flows[flow_key]
        dst_ports_count = len(flow['dst_ports'])
        scan_percent = flow['scan_percent']
        avg_packet_port = flow['avg_packets_per_dst_port']

        # Check if TCP Port Scan Heavy/Light
        if dst_ports_count >= N2 and scan_percent >= R and avg_packet_port > M:
            heavy_port_scan += 1
        elif dst_ports_count > N2 and scan_percent >= R and avg_packet_port <= M:
            light_port_scan += 1

    print(f"Heavy port scans: {heavy_port_scan}")
    print(f"Light port scans: {light_port_scan}")




def tcp_network_scan(tcp_srcs):
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

        # Check if TCP Port Scan Heavy/Light
        if dst_ips_count >= N1 and scan_percent >= R and avg_packet_ip > M:
            heavy_network_scan += 1
        elif dst_ips_count > N1 and scan_percent >= R and avg_packet_ip <= M:
            light_network_scan += 1

    print(f"Heavy network scans: {heavy_network_scan}")
    print(f"Light network scans: {light_network_scan}")

def one_flow(tcp_one_flows):
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
    
        if packets >= N3:
            tcp_one_flow += 1

    print(f"TCP One Flows: {tcp_one_flow}")  

def tcp_backscatter(tcp_backscatters):
    '''
    Check number of backscatter
    '''

    num_ips = len(tcp_backscatters)
    print(f"TCP backscatter connections: {num_ips}")

def small_syn(small_syns):
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
    
        if dst_ips_count < N1 and dst_ports_count < N2 and packets <= N3:
            Small_SYN += 1

    print(f"Small SYN: {Small_SYN}") 


    