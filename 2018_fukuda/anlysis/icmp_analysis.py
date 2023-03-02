def icmp_network_scan(icmp_srcs, icmp_other):
    '''
    Check if flow is Network Scan
    Returns:
        Number of packets that is Network Scan
    '''
    flows = icmp_srcs
    heavy_network_scan = 0
    light_network_scan = 0
    N1 = 5
    R = 0.50
    M = 3

    for flow_key in flows:
        flow = flows[flow_key]
        dst_ips_count = len(flow['dst_ips'])
        avg_packet_ip = flow['avg_packets_per_dst_ip']
        src_ip = flow_key[0]

        # Check if icmp Port Scan Heavy/Light
        if dst_ips_count >= N1 and avg_packet_ip > M:
            heavy_network_scan += 1
        elif dst_ips_count > N1 and avg_packet_ip <= M:
            light_network_scan += 1
        else:
            icmp_other.add(src_ip)


    print(f"Heavy network scans: {heavy_network_scan}")
    print(f"Light network scans: {light_network_scan}")

def icmp_backscatter(icmp_backscatters):
    '''
    Check number of backscatter
    '''

    num_ips = len(icmp_backscatters)
    print(f"icmp backscatter connections: {num_ips}")

def icmp_fragment(icmp_srcs, icmp_other):
    flows = icmp_srcs
    frag_connections = 0

    for flow_key in flows:
        flow = flows[flow_key]
        frag_packet = flow['frag_packets']
        src_ip = flow_key[0]

        if frag_packet >= 1:
            frag_connections += 1
            if src_ip in icmp_other:
                icmp_other.remove(src_ip)
        else:
            icmp_other.add(src_ip)

    print(f"IP Fragement: {frag_connections}")
    return icmp_other

def small_ping(small_pings, icmp_other):
    '''
    Check for Small icmp
    Returns:
        Number of Samll icmp
    '''
    flows = small_pings
    Small_ping = 0
    N1 = 5
    N2 = 5
    N3 = 15

    for flow_key in flows:
        flow = flows[flow_key]  
        dst_ips_count = len(flow['dst_ips'])
        packets = flow['num_packets']
        src_ip = flow_key[0]
    
        if dst_ips_count < N1 and packets <= N3:
            Small_ping += 1
            if src_ip in icmp_other:
                icmp_other.remove(src_ip)
        else:
            icmp_other.add(src_ip)

    print(f"Small icmp: {Small_ping}")
    return icmp_other 