def udp_speed(udp_flows):
    '''
    Compare streams to find: 
        Ports + distrubution
    '''
    
    udp_slow = {}
    udp_medium = {}
    udp_rapid = {}

    for flow, packets in udp_flows.items():
        avg_time = packets[0]['avg_time_between_packets']
        if avg_time >= 5:
            udp_slow[flow] = packets
        elif avg_time >= 1:
            udp_medium[flow] = packets
        else:
            udp_rapid[flow] = packets
