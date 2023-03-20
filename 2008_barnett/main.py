import dpkt
from functools import reduce
import socket
from datetime import datetime
import time
from flows import tcp_traffic, udp_traffic, icmp_traffic

packets = 0
minutes = 0
start_time = time.time()
total_packets = 0

# TCP Dicts
tcp_flows = {}
# tcp speed checks
tcp_slow = {}
tcp_medium = {}
tcp_rapid = {}
# tcp dist step 1
tcp_compare_slow = {}
tcp_compare_medium = {}
tcp_compare_rapid = {}
# tcp dist step 2
tcp_dist_slow = {}
tcp_dist_medium = {}
tcp_dist_rapid = {}


# UDP Dicts
udp_flows = {}
# udp speed check
udp_slow = {}
udp_medium = {}
udp_rapid = {}
# udp dist step 1
udp_compare_slow = {}
udp_compare_medium = {}
udp_compare_rapid = {}
# udp dist step 2
udp_dist_slow = {}
udp_dist_medium = {}
udp_dist_rapid = {}

# ICMP Dicts
icmp_flows = {}
# icmp speed checks
icmp_slow = {}
icmp_medium = {}
icmp_rapid = {}
# icmp dist step 1
icmp_compare_slow = {}
icmp_compare_medium = {}
icmp_compare_rapid = {}
# icmp dist step 2
icmp_dist_slow = {}
icmp_dist_medium = {}
icmp_dist_rapid = {}

# set of ip's
ip_src = set()

#for ts, pkt in dpkt.pcap.Reader(open('data/output_file_00000_20191203121948.pcap', 'rb')):
for ts, pkt in dpkt.pcap.Reader(open('data/smallcap_00001_20191204021309.pcap', 'rb')):
#for ts,pkt in dpkt.pcap.Reader(open('data/CaptureOne.pcap','rb')):
    packets += 1
    total_packets += 1 
    eth=dpkt.ethernet.Ethernet(pkt)
    ip = eth.data

    if eth.type==dpkt.ethernet.ETH_TYPE_IP:   
        if socket.inet_ntoa(ip.src) not in ip_src:
            ip_src.add(socket.inet_ntoa(ip.src))
        # determine transport layer type
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            # extract IP and transport layer data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)


            if isinstance(ip.data, dpkt.tcp.TCP):
                src_port = ip.data.sport
                dst_port = ip.data.dport

                flows = tcp_flows
                # store flow data
                flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
                flow = (flow[0], flow[1])

                if flows.get(flow):
                    flow_data = flows[flow][-1]
                    flow_data['packet_count'] += 1
                    flow_data['SYN_count'] += 1 if ip.data.flags & dpkt.tcp.TH_SYN else 0
                    flow_data['ACK_count'] += 1 if ip.data.flags & dpkt.tcp.TH_ACK else 0
                    flow_data['FIN_count'] += 1 if ip.data.flags & dpkt.tcp.TH_FIN else 0
                    flow_data['last_packet'] = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                    flow_data['timestamps'].append(ts)
                    if len(flow_data['timestamps']) > 1:
                        first_ts = flow_data['timestamps'][0]
                        last_ts = flow_data['timestamps'][-1]
                        time_diff = (last_ts - first_ts) / (len(flow_data['timestamps']) - 1)
                        flow_data['avg_time_between_packets'] = time_diff
                else:
                    flows[flow] = [{
                        'packet_count': 1,
                        'SYN_count': 1 if ip.data.flags & dpkt.tcp.TH_SYN else 0,
                        'ACK_count': 1 if ip.data.flags & dpkt.tcp.TH_ACK else 0,
                        'FIN_count': 1 if ip.data.flags & dpkt.tcp.TH_FIN else 0,
                        'first_packet': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f'),
                        'last_packet': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f'),
                        'timestamps': [ts],
                        'avg_time_between_packets': 0
                    }]

        elif ip.p == dpkt.ip.IP_PROTO_UDP:

            # extract IP and transport layer data
            src_ip = socket.inet_ntoa(ip.src)
            src_port = ip.data.sport
            dst_ip = socket.inet_ntoa(ip.dst)
            dst_port = ip.data.dport

            ips.add(src_ip)
            ips.add(dst_ip)

            flows = udp_flows
            # store flow data
            flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
            flow = (flow[0], flow[1])

            if flows.get(flow):
                flow_data = flows[flow][-1]
                flow_data['packet_count'] += 1
                flow_data['last_packet'] = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                flow_data['timestamps'].append(ts)
                if len(flow_data['timestamps']) > 1:
                    first_ts = flow_data['timestamps'][0]
                    last_ts = flow_data['timestamps'][-1]
                    time_diff = (last_ts - first_ts) / (len(flow_data['timestamps']) - 1)
                    flow_data['avg_time_between_packets'] = time_diff
            else:
                flows[flow] = [{
                    'packet_count': 1,
                    'first_packet': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f'),
                    'last_packet': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f'),
                    'timestamps': [ts],
                    'avg_time_between_packets': 0
                }]
        
        elif ip.p == dpkt.ip.IP_PROTO_ICMP:

            # extract IP and transport layer data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)

            ips.add(src_ip)
            ips.add(dst_ip)
            
            flows = icmp_flows
            # store flow data
            flow = sorted([(src_ip), (dst_ip)])
            flow = (flow[0], flow[1])

            if flows.get(flow):
                flow_data = flows[flow][-1]
                flow_data['packet_count'] += 1
                flow_data['Pings'] += 1 if ip.icmp.type == 8 else 0
                flow_data['last_packet'] = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                flow_data['timestamps'].append(ts)
                if len(flow_data['timestamps']) > 1:
                    first_ts = flow_data['timestamps'][0]
                    last_ts = flow_data['timestamps'][-1]
                    time_diff = (last_ts - first_ts) / (len(flow_data['timestamps']) - 1)
                    flow_data['avg_time_between_packets'] = time_diff
            else:
                flows[flow] = [{
                    'packet_count': 1,
                    'Pings': 1 if ip.icmp.type == 8 and ip.icmp.code == 8 else 0,
                    'first_packet': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f'),
                    'last_packet': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f'),
                    'timestamps': [ts],
                    'avg_time_between_packets': 0
                }]
    
        else:
            print('hello')
    # Counter of packets each minute
    elapsed_time = time.time() - start_time
    if elapsed_time > 60:
        minutes += 1
        if minutes == 1:    
            print(f"Number of packets processed in the {minutes}st minute:", packets)
        elif minutes == 2:
            print(f"Number of packets processed in the {minutes}nd minute:", packets)
        elif minutes == 3:
            print(f"Number of packets processed in the {minutes}rd minute:", packets)
        else:
            print(f"Number of packets processed in the {minutes}th minute:", packets)
        packets = 0
        start_time = time.time()
        
# check scanning speed
tcp_traffic.tcp_speed(tcp_flows, tcp_slow, tcp_medium, tcp_rapid)
udp_traffic.udp_speed(udp_flows, udp_slow, udp_medium, udp_rapid)
icmp_traffic.icmp_speed(icmp_flows, icmp_slow, icmp_medium, icmp_rapid)
# Check for tcp distrubution step 1: one-to-one and one-to-many
# TCP
tcp_traffic.tcp_compare_src(tcp_slow, tcp_compare_slow)
tcp_traffic.tcp_compare_src(tcp_medium, tcp_compare_medium)
tcp_traffic.tcp_compare_src(tcp_rapid, tcp_compare_rapid)
# UDP
udp_traffic.udp_compare_src(udp_slow, udp_compare_slow)
udp_traffic.udp_compare_src(udp_medium, udp_compare_medium)
udp_traffic.udp_compare_src(udp_rapid, udp_compare_rapid)
#print(udp_compare_slow)
# ICMP
icmp_traffic.icmp_compare_src(icmp_slow, icmp_compare_slow)
icmp_traffic.icmp_compare_src(icmp_medium, icmp_compare_medium)
icmp_traffic.icmp_compare_src(icmp_rapid, icmp_compare_rapid)
#print(icmp_compare_slow)

# check for tcp distrubution step 2: one-to-many and many-to-may
# TCP
tcp_traffic.find_dist(tcp_compare_slow, tcp_dist_slow)
tcp_traffic.find_dist(tcp_compare_medium, tcp_dist_medium)
tcp_traffic.find_dist(tcp_compare_rapid, tcp_dist_rapid)
#print(tcp_dist_slow)
# UDP
udp_traffic.find_dist(udp_compare_slow, udp_dist_slow)
udp_traffic.find_dist(udp_compare_medium, udp_dist_medium)
udp_traffic.find_dist(udp_compare_rapid, udp_dist_rapid)
#print(udp_dist_slow)
# ICMP
icmp_traffic.find_dist(icmp_compare_slow, icmp_dist_slow)
icmp_traffic.find_dist(icmp_compare_medium, icmp_dist_medium)
icmp_traffic.find_dist(icmp_compare_rapid, icmp_dist_rapid)
print(udp_dist_slow)


print("---------------------")
print('PCAP info:')
print(f'Number of packets: {total_packets}')
print("---------------------")
#print(f'Total TCP flows: {tcp_flows}')
print(f'Total TCP flows: {len(tcp_flows.keys())}')
print("---------------------")
#print(f'Total UDP flows: {udp_flows}')
print(f'Total UDP flows: {len(udp_flows.keys())}')
print("---------------------")
#print(f'Total ICMP flows: {icmp_flows}')
print(f'Total ICMP flows: {len(icmp_flows.keys())}')
print("---------------------")
print(f'Total IPs: {len(ips)}')

