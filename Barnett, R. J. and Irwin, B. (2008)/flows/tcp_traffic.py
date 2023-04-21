from datetime import datetime


def tcp_compare_src(tcp_flows, tcp_compare_flows):
    '''
    Function to compare ip src to put togheter scan flows from different ports
    Input:
        tcp_flows
    Returns:
        tcp_compare_flow
    '''

    # iterate through the tcp_slow dictionary
    for key, value in tcp_flows.items():
        # extract the source IP address, destination IP address, and destination port
        src_ip = key[0][0]
        dst_ip = key[1][0]
        dst_port = key[1][1]
        # avg_time = key[]
        # extract the packet counts for each flag
        syn_count = value[0]['SYN_count']
        ack_count = value[0]['ACK_count']
        fin_count = value[0]['FIN_count']

        # create a tuple to represent the flow key
        flow_key = (src_ip)

        # check if this flow key already exists in the tcp_compare_flows
        if flow_key in tcp_compare_flows:
            # if it does, update the existing flow
            flow = tcp_compare_flows[flow_key]
            flow['packet_count'] += value[0]['packet_count']
            flow['SYN_count'] += syn_count
            flow['ACK_count'] += ack_count
            flow['FIN_count'] += fin_count

            # Update Scan periode
            if value[0]['first_packet'] < flow['first_packet']:
                flow['first_packet'] = value[0]['first_packet']
                first_hour = datetime.strptime(
                    value[0]['first_packet'], '%Y-%m-%d %H:%M:%S.%f')
                flow['scan_periode-1'] = first_hour.strftime('%d-%H-%M')
            if value[0]['last_packet'] > flow['last_packet']:
                flow['last_packet'] = value[0]['last_packet']
                last_hour = datetime.strptime(
                    value[0]['last_packet'], '%Y-%m-%d %H:%M:%S.%f')
                flow['scan_periode-2'] = last_hour.strftime('%d-%H-%M')

            # Find average time between packets
            if flow['packet_count'] > 0:
                time_diff = datetime.strptime(
                    flow['last_packet'], '%Y-%m-%d %H:%M:%S.%f') - datetime.strptime(flow['first_packet'], '%Y-%m-%d %H:%M:%S.%f')
                avg_time = time_diff / (flow['packet_count'] - 1)
                flow['avg_time_between_packets'] = round(
                    avg_time.total_seconds(), 2)
                
            if dst_ip not in flow['ip_dst']:
                flow['ip_dst'].append(dst_ip)
            if dst_port not in flow['dst_ports']:
                flow['dst_ports'].append(dst_port)

        else:
            first_hour = datetime.strptime(
                value[0]['first_packet'], '%Y-%m-%d %H:%M:%S.%f')
            last_hour = datetime.strptime(
                value[0]['last_packet'], '%Y-%m-%d %H:%M:%S.%f')

            # if it doesn't, create a new flow
            tcp_compare_flows[flow_key] = {
                'ip_dst': [dst_ip],
                'dst_ports': [dst_port],
                'packet_count': value[0]['packet_count'],
                'SYN_count': syn_count,
                'ACK_count': ack_count,
                'FIN_count': fin_count,
                'ip_src_count': 1,
                'first_packet': value[0]['first_packet'],
                'last_packet': value[0]['last_packet'],
                'avg_time_between_packets': 0,
                'scan_periode-1': first_hour.strftime('%d-%H-%M'),
                'scan_periode-2': last_hour.strftime('%d-%H-%M')

            }
    return tcp_compare_flows


def tcp_speed(tcp_compare_flows, tcp_slow, tcp_medium, tcp_rapid):
    '''
    Function to find speed of scan, based on average time between packets.
    Speeds are based on Nmap: https://nmap.org/book/performance-timing-templates.html
    Input:
        tcp_compare_flows
    Returns:
        tcp_slow
        tcp_medium
        tcp_rapid
    '''

    for flow, packets in tcp_compare_flows.items():
        avg_time = packets['avg_time_between_packets']
        if avg_time >= 5:
            tcp_slow[flow] = packets
        elif avg_time >= 1:
            tcp_medium[flow] = packets
        else:
            tcp_rapid[flow] = packets

    return tcp_slow, tcp_medium, tcp_rapid


def find_dist(speed_lists, final_dist):
    '''
    Function to compare destination IPs to find sitrubution
    Input:
        Takes in one three speed_lists
        speeed_lists
    Returns:
        Final Distrubution list
        final_dist
    '''
    # iterate through the tcp_slow dictionary
    for key, value in speed_lists.items():
        # extract the source IP address, destination IP address, and destination port
        src_ip = key
        dst_ips = value['ip_dst']
        dst_port = value['dst_ports']
        if len(value['dst_ports']) > 1:
            ports = 'many'
        else:
            ports = 'one'

        # Establish pariode of scan
        scan_periode1 = value['scan_periode-1']
        scan_periode2 = value['scan_periode-2']
        # extract the packet counts for each flag
        syn_count = value['SYN_count']
        ack_count = value['ACK_count']
        fin_count = value['FIN_count']
        time = value['avg_time_between_packets']

        flow_key = (tuple(dst_ips), ports, scan_periode1, scan_periode2)

        # check if this flow key already exists in the final_dist
        if flow_key in final_dist:
            # if it does, update the existing flow
            flow = final_dist[flow_key]
            flow['packet_count'] += value['packet_count']
            flow['ip_src_count'] += 1
            flow['SYN_count'] += syn_count
            flow['ACK_count'] += ack_count
            flow['FIN_count'] += fin_count
            avg_time = flow['avg_time_between_packets']
            new_avg_time = time
            if avg_time <= 0:
                flow['avg_time_between_packets'] = new_avg_time
            elif new_avg_time != 0:
                flow['avg_time_between_packets'] = (
                    avg_time + new_avg_time) / 2
            if value['first_packet'] < flow['first_packet']:
                flow['first_packet'] = value['first_packet']
            if value['last_packet'] > flow['last_packet']:
                flow['last_packet'] = value['last_packet']
            if src_ip not in flow['src_ips']:
                flow['src_ips'].append(src_ip)
            if dst_port not in flow['dst_ports']:
                flow['dst_ports'].append(dst_port)
        else:
            # if it doesn't add to flow, create a new flow
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
                'avg_time_between_packets': value['avg_time_between_packets']
            }
    return final_dist


def group_dist(final_dist, one_to_one, one_to_many, many_to_one, many_to_many):
    '''
    Function to place flows groups for distrubution
    Input:
        final_dist
    Returns:
        one-to-one
        one-to-many
        many-to-one
        many-to-many
    '''
    
    for key, value in final_dist.items():
        num_dst_ips = len(key[0])
        num_src_ips = value['ip_src_count']

        # Get desired key-value pairs
        dst_ports = value['dst_ports']
        src_ip = value['src_ips']
        ip_src_count = value['ip_src_count']
        packet_count = value['packet_count']
        syn = value['SYN_count']
        ack = value['ACK_count']
        fin = value['FIN_count']
        avg_time_between_packets = value['avg_time_between_packets']

        # Categorize based on number of destination IPs and source IPs
        if num_dst_ips == 1 and num_src_ips == 1:
            one_to_one[key] = {'dst_ports': dst_ports, 'src_ips': src_ip, 'ip_src_count': ip_src_count, 'packet_count': packet_count,
                               'syn_count': syn, 'ack_count': ack, 'fin_count': fin, 'avg_time_between_packets': avg_time_between_packets}
        elif num_dst_ips == 1 and num_src_ips > 1:
            many_to_one[key] = {'dst_ports': dst_ports, 'src_ips': src_ip, 'ip_src_count': ip_src_count, 'packet_count': packet_count,
                                'syn_count': syn, 'ack_count': ack, 'fin_count': fin, 'avg_time_between_packets': avg_time_between_packets}
        elif num_dst_ips > 1 and num_src_ips == 1:
            one_to_many[key] = {'dst_ports': dst_ports, 'src_ips': src_ip,
                                 'ip_src_count': ip_src_count, 'packet_count': packet_count,
                                 'syn_count': syn, 'ack_count': ack, 'fin_count': fin,
                                 'avg_time_between_packets': avg_time_between_packets}
        elif num_dst_ips > 1 and num_src_ips > 1:
            many_to_many[key] = {'dst_ports': dst_ports, 'src_ips': src_ip,
                                  'ip_src_count': ip_src_count, 'packet_count': packet_count,
                                  'syn_count': syn, 'ack_count': ack, 'fin_count': fin,
                                  'avg_time_between_packets': avg_time_between_packets}

    return one_to_one, one_to_many, many_to_one, many_to_many


def tcp_flags(dist, other, syn_list, ack_list, fin_list):
    '''
    Function to place flows groups for distrubution and flags
    Input:
        final_dist
    Returns:
        other
        syn_list
        ack_list
        fin_lsist
    '''

    for key, value in dist.items():
        dst_ports = value['dst_ports']
        src_ip = value['src_ips']
        ip_src_count = value['ip_src_count']
        packet_count = value['packet_count']
        syn = value['syn_count']
        ack = value['ack_count']
        fin = value['fin_count']
        avg_time_between_packets = value['avg_time_between_packets']

    # Checks to find SYN, ACK or FIN
        if syn > 1 and ack == 0 and fin == 0:
            syn_list[key] = {'dst_ports': dst_ports, 'src_ip': src_ip, 'ip_src_count': ip_src_count, 'packet_count': packet_count,
                             'syn_count': syn, 'ack_count': ack, 'fin_count': fin, 'avg_time_between_packets': avg_time_between_packets}

        elif ack > 1 and fin == 0:
            ack_list[key] = {'dst_ports': dst_ports, 'src_ip': src_ip, 'ip_src_count': ip_src_count, 'packet_count': packet_count,
                             'syn_count': syn, 'ack_count': ack, 'fin_count': fin, 'avg_time_between_packets': avg_time_between_packets}

        elif fin > 1:
            fin_list[key] = {'dst_ports': dst_ports,  'src_ip': src_ip, 'ip_src_count': ip_src_count, 'packet_count': packet_count,
                             'syn_count': syn, 'ack_count': ack, 'fin_count': fin, 'avg_time_between_packets': avg_time_between_packets}

        else:
            other[key] = {'dst_ports': dst_ports,  'src_ip': src_ip, 'ip_src_count': ip_src_count, 'packet_count': packet_count,
                          'syn_count': syn, 'ack_count': ack, 'fin_count': fin, 'avg_time_between_packets': avg_time_between_packets}

    return other, syn_list, ack_list, fin_list
