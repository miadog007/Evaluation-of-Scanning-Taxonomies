from datetime import datetime

def icmp_speed(icmp_flows, icmp_slow, icmp_medium, icmp_rapid):
    '''
    Compare streams to find: 
        Ports + distrubution
    '''

    for flow, packets in icmp_flows.items():
        avg_time = packets[0]['avg_time_between_packets']
        if avg_time >= 5:
            icmp_slow[flow] = packets
        elif avg_time >= 1:
            icmp_medium[flow] = packets
        else:
            icmp_rapid[flow] = packets

    #print(icmp_slow)
    return icmp_slow, icmp_medium, icmp_rapid

def icmp_compare_src(speed_list, icmp_compare_flows):
    '''
    Function to compare ip src to put togheter
    '''

    # iterate through the icmp_slow dictionary
    for key, value in speed_list.items():
        # extract the source IP address, destination IP address
        src_ip = key[0]
        dst_ip = key[1]
 

        time = value[0]['avg_time_between_packets']

        # create a tuple to represent the flow key
        flow_key = (src_ip)

        # check if this flow key already exists in the icmp_compare_flows
        if flow_key in icmp_compare_flows:
            # if it does, update the existing flow
            flow = icmp_compare_flows[flow_key]
            flow['packet_count'] += value[0]['packet_count']
            #flow['timestamps'].extend(value[0]['timestamps'])
            avg_time = flow['avg_time_between_packets']
            new_avg_time = time
            if avg_time <= 0:
                flow['avg_time_between_packets'] = new_avg_time
            elif new_avg_time !=0:
                flow['avg_time_between_packets'] = (avg_time + new_avg_time) / 2
            if value[0]['first_packet'] < flow['first_packet']:
                flow['first_packet'] = value[0]['first_packet']
                first_hour = datetime.strptime(value[0]['first_packet'], '%Y-%m-%d %H:%M:%S.%f')
                flow['scan_periode-1'] = first_hour.strftime('%d-%H-%M')
            if value[0]['last_packet'] > flow['last_packet']:
                flow['last_packet'] = value[0]['last_packet']
                last_hour = datetime.strptime(value[0]['last_packet'], '%Y-%m-%d %H:%M:%S.%f')
                flow['scan_periode-2'] = last_hour.strftime('%d-%H-%M')
            if dst_ip not in flow['ip_dst']:
                flow['ip_dst'].append(dst_ip)
        else:
            first_hour = datetime.strptime(value[0]['first_packet'], '%Y-%m-%d %H:%M:%S.%f')
            last_hour = datetime.strptime(value[0]['last_packet'], '%Y-%m-%d %H:%M:%S.%f')
            # if it doesn't, create a new flow
            icmp_compare_flows[flow_key] = {
                'ip_dst': [dst_ip],
                'packet_count': value[0]['packet_count'],
                'first_packet': value[0]['first_packet'],
                'last_packet': value[0]['last_packet'],
                #'timestamps': value[0]['timestamps'],
                'avg_time_between_packets': value[0]['avg_time_between_packets'],
                'scan_periode-1': first_hour.strftime('%d-%H-%M'),
                'scan_periode-2': last_hour.strftime('%d-%H-%M')
            }

    return icmp_compare_flows
    


def find_dist(icmp_compare_flows, final_dist):
    '''
    Find final dist
    '''
    # iterate through the icmp_slow dictionary
    for key, value in icmp_compare_flows.items():
        # extract the source IP address and destination IP address
        src_ip = key
        dst_ips = value['ip_dst']
        scan_periode1 = value['scan_periode-1']
        scan_periode2 = value['scan_periode-2']

        time = value['avg_time_between_packets']
        # create a tuple to represent the flow key
        flow_key = (tuple(dst_ips), scan_periode1, scan_periode2)

        # check if this flow key already exists in the final_dist
        if flow_key in final_dist:
            # if it does, update the existing flow
            flow = final_dist[flow_key]
            flow['packet_count'] += value['packet_count']
            flow['ip_src_count'] += 1
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
        else:
            # if it doesn't, create a new flow
            final_dist[flow_key] = {
                'src_ips': [src_ip],
                'ip_src_count': 1,
                'packet_count': value['packet_count'],
                'first_packet': value['first_packet'],
                'last_packet': value['last_packet'],
                #'timestamps': value[0]['timestamps'],
                'avg_time_between_packets': value['avg_time_between_packets']
            }

    return final_dist

def group_dist(final_dist, one_to_one, one_to_many, many_to_one, many_to_many):
    for key, value in final_dist.items():
        num_dst_ips = len(key[0])
        num_src_ips = value['ip_src_count']

        # Get desired key-value pairs
        src_ip = value['src_ips']
        ip_src_count = value['ip_src_count']
        packet_count = value['packet_count']
        avg_time_between_packets = value['avg_time_between_packets']
        
        # Categorize based on number of destination IPs and source IPs
        if num_dst_ips == 1 and num_src_ips == 1:
            dst_ip = key
            one_to_one[dst_ip] = {'src_ip': src_ip, 'ip_src_count': ip_src_count, 'packet_count': packet_count, 'avg_time_between_packets': avg_time_between_packets}
        elif num_dst_ips == 1 and num_src_ips > 1:
            dst_ip = key
            many_to_one[dst_ip] = {'src_ips': src_ip, 'ip_src_count': ip_src_count, 'packet_count': packet_count, 'avg_time_between_packets': avg_time_between_packets}
        elif num_dst_ips > 1 and num_src_ips == 1:
            dst_ip = key
            one_to_many[dst_ip] = {'src_ip': src_ip, 'ip_src_count': ip_src_count, 'packet_count': packet_count, 'avg_time_between_packets': avg_time_between_packets}
        elif num_dst_ips > 1 and num_src_ips > 1:
            dst_ip = key
            many_to_many[dst_ip] = {'src_ips': src_ip, 'ip_src_count': ip_src_count, 'packet_count': packet_count, 'avg_time_between_packets': avg_time_between_packets}

    return one_to_one, one_to_many, many_to_one, many_to_many
