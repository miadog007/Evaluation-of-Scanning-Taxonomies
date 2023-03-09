def tcp_speed(tcp_flows, tcp_slow, tcp_medium, tcp_rapid):
    '''
    Compare streams to find: 
        Ports + distrubution
    '''

    for flow, packets in tcp_flows.items():
        avg_time = packets[0]['avg_time_between_packets']
        if avg_time >= 5:
            tcp_slow[flow] = packets
        elif avg_time >= 1:
            tcp_medium[flow] = packets
        else:
            tcp_rapid[flow] = packets

    #print(tcp_slow)
    return tcp_slow, tcp_medium, tcp_rapid

def tcp_compare_src(speed_list, tcp_compare_flows):
    '''
    Function to compare ip src to put togheter scan flows from different ports
    '''

    # iterate through the tcp_slow dictionary
    for key, value in speed_list.items():
        # extract the source IP address, destination IP address, and destination port
        src_ip = key[0][0]
        dst_ip = key[1][0]
        dst_port = key[1][1]
        #avg_time = key[]
        # extract the packet counts for each flag
        syn_count = value[0]['SYN_count']
        ack_count = value[0]['ACK_count']
        fin_count = value[0]['FIN_count']

        time = value[0]['avg_time_between_packets']

        # determine the flags for this flow
        if syn_count > 0 and ack_count == 0 and fin_count == 0:
            flags = 'SYN'
        elif syn_count == 0 and ack_count > 0 and fin_count == 0:
            flags = 'ACK'
        elif syn_count == 0 and ack_count == 0 and fin_count > 0:
            flags = 'FIN'
        elif syn_count > 0 and ack_count > 0 and fin_count == 0:
            flags = 'SYN-ACK'
        elif syn_count == 0 and ack_count > 0 and fin_count > 0:
            flags = 'FIN-ACK'
        elif syn_count > 0 and ack_count == 0 and fin_count > 0:
            flags = 'SYN-FIN'
        else:
            flags = 'Other'

        # create a tuple to represent the flow key
        flow_key = (src_ip, flags)

        # check if this flow key already exists in the tcp_compare_flows
        if flow_key in tcp_compare_flows:
            # if it does, update the existing flow
            flow = tcp_compare_flows[flow_key]
            flow['packet_count'] += value[0]['packet_count']
            flow['SYN_count'] += syn_count
            flow['ACK_count'] += ack_count
            flow['FIN_count'] += fin_count
            #flow['timestamps'].extend(value[0]['timestamps'])
            avg_time = flow['avg_time_between_packets']
            new_avg_time = time
            if avg_time <= 0:
                flow['avg_time_between_packets'] = new_avg_time
            elif new_avg_time !=0:
                flow['avg_time_between_packets'] = (avg_time + new_avg_time) / 2
            if value[0]['first_packet'] < flow['first_packet']:
                flow['first_packet'] = value[0]['first_packet']
            if value[0]['last_packet'] > flow['last_packet']:
                flow['last_packet'] = value[0]['last_packet']
            if dst_ip not in flow['ip_dst']:
                flow['ip_dst'].append(dst_ip)
            if dst_port not in flow['dst_ports']:
                flow['dst_ports'].append(dst_port)
        else:
            # if it doesn't, create a new flow
            tcp_compare_flows[flow_key] = {
                'ip_dst': [dst_ip],
                'dst_ports': [dst_port],
                'packet_count': value[0]['packet_count'],
                'SYN_count': syn_count,
                'ACK_count': ack_count,
                'FIN_count': fin_count,
                'first_packet': value[0]['first_packet'],
                'last_packet': value[0]['last_packet'],
                #'timestamps': value[0]['timestamps'],
                'avg_time_between_packets': value[0]['avg_time_between_packets']
            }

    return tcp_compare_flows
    


def find_dist(tcp_compare_flows, final_dist):
    '''
    Find final dist
    '''
    # iterate through the tcp_slow dictionary
    for key, value in tcp_compare_flows.items():
        # extract the source IP address, destination IP address, and destination port
        flags = key[1]
        src_ip = key[0]
        dst_ips = value['ip_dst']
        dst_port = value['dst_ports']
        # extract the packet counts for each flag
        syn_count = value['SYN_count']
        ack_count = value['ACK_count']
        fin_count = value['FIN_count']
        time = value['avg_time_between_packets']
        flags_str = "".join(str(f) for f in flags)
        # create a tuple to represent the flow key
        flow_key = (tuple(dst_ips), flags_str)

        # check if this flow key already exists in the final_dist
        if flow_key in final_dist:
            # if it does, update the existing flow
            flow = final_dist[flow_key]
            flow['packet_count'] += value['packet_count']
            flow['ip_src_count'] += 1
            flow['SYN_count'] += syn_count
            flow['ACK_count'] += ack_count
            flow['FIN_count'] += fin_count
            #flow['timestamps'].extend(value[0]['timestamps'])
            avg_time = flow['avg_time_between_packets']
            new_avg_time = time
            if avg_time <= 0:
                flow['avg_time_between_packets'] = new_avg_time
            elif new_avg_time !=0:
                flow['avg_time_between_packets'] = (avg_time + new_avg_time) / 2
            if value['first_packet'] < flow['first_packet']:
                flow['first_packet'] = value['first_packet']
            if value['last_packet'] > flow['last_packet']:
                flow['last_packet'] = value['last_packet']
            if src_ip not in flow['src_ips']:
                flow['src_ips'].append(src_ip)
            if dst_port not in flow['dst_ports']:
                flow['dst_ports'].append(dst_port)
        else:
            # if it doesn't, create a new flow
            final_dist[flow_key] = {
                'dst_ports': [dst_port],
                'src_ips': [src_ip],
                'ip_src_count': 1,
                'packet_count': value['packet_count'],
                'SYN_count': syn_count,
                'ACK_count': ack_count,
                'FIN_count': fin_count,
                'first_packet': value['first_packet'],
                'last_packet': value['last_packet'],
                #'timestamps': value[0]['timestamps'],
                'avg_time_between_packets': value['avg_time_between_packets']
            }

    return final_dist


# 159.203.201.179