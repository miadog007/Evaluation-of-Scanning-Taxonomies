def icmp_speed(icmp_flows):
    '''
    Compare streams to find: 
        Ports + distrubution
    '''
    
    icmp_slow = {}
    icmp_medium = {}
    icmp_rapid = {}

    for flow, packets in icmp_flows.items():
        avg_time = packets[0]['avg_time_between_packets']
        if avg_time >= 5:
            icmp_slow[flow] = packets
        elif avg_time >= 1:
            icmp_medium[flow] = packets
        else:
            icmp_rapid[flow] = packets