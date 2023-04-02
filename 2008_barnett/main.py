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
tcp_compare = {}

# tcp dist step 2
tcp_dist_slow = {}
tcp_dist_medium = {}
tcp_dist_rapid = {}
# tcp final stats
#Slow
tcp_onetoone_slow = {}
tcp_onetomany_slow = {}
tcp_manytoone_slow = {}
tcp_manytomany_slow = {}
#Medium
tcp_onetoone_medium = {}
tcp_onetomany_medium = {}
tcp_manytoone_medium = {}
tcp_manytomany_medium = {}
#rapid
tcp_onetoone_rapid = {}
tcp_onetomany_rapid = {}
tcp_manytoone_rapid = {}
tcp_manytomany_rapid = {}
# tcp special
# slow
tcp_oto_slow = {}
tcp_oto_slow_syn = {}
tcp_oto_slow_ack = {}
tcp_oto_slow_fin = {}

tcp_otm_slow = {}
tcp_otm_slow_syn = {}
tcp_otm_slow_ack = {}
tcp_otm_slow_fin = {}

tcp_mto_slow = {}
tcp_mto_slow_syn = {}
tcp_mto_slow_ack = {}
tcp_mto_slow_fin = {}

tcp_mtm_slow = {}
tcp_mtm_slow_syn = {}
tcp_mtm_slow_ack = {}
tcp_mtm_slow_fin = {}
# medium
tcp_oto_medium = {}
tcp_oto_medium_syn = {}
tcp_oto_medium_ack = {}
tcp_oto_medium_fin = {}

tcp_otm_medium = {}
tcp_otm_medium_syn = {}
tcp_otm_medium_ack = {}
tcp_otm_medium_fin = {}

tcp_mto_medium = {}
tcp_mto_medium_syn = {}
tcp_mto_medium_ack = {}
tcp_mto_medium_fin = {}

tcp_mtm_medium = {}
tcp_mtm_medium_syn = {}
tcp_mtm_medium_ack = {}
tcp_mtm_medium_fin = {}
# rapid
tcp_oto_rapid = {}
tcp_oto_rapid_syn = {}
tcp_oto_rapid_ack = {}
tcp_oto_rapid_fin = {}

tcp_otm_rapid = {}
tcp_otm_rapid_syn = {}
tcp_otm_rapid_ack = {}
tcp_otm_rapid_fin = {}

tcp_mto_rapid = {}
tcp_mto_rapid_syn = {}
tcp_mto_rapid_ack = {}
tcp_mto_rapid_fin = {}

tcp_mtm_rapid = {}
tcp_mtm_rapid_syn = {}
tcp_mtm_rapid_ack = {}
tcp_mtm_rapid_fin = {}

# UDP Dicts
udp_flows = {}
# UDP speed check
udp_slow = {}
udp_medium = {}
udp_rapid = {}
# UDP dist step 1
udp_compare_slow = {}
udp_compare_medium = {}
udp_compare_rapid = {}
udp_compare = {}
# UDP dist step 2
udp_dist_slow = {}
udp_dist_medium = {}
udp_dist_rapid = {}
# UDP final stats
#Slow
udp_onetoone_slow = {}
udp_onetomany_slow = {}
udp_manytoone_slow = {}
udp_manytomany_slow = {}
#Medium
udp_onetoone_medium = {}
udp_onetomany_medium = {}
udp_manytoone_medium = {}
udp_manytomany_medium = {}
#rapid
udp_onetoone_rapid = {}
udp_onetomany_rapid = {}
udp_manytoone_rapid = {}
udp_manytomany_rapid = {}

# ICMP Dicts
icmp_flows = {}
# ICMP speed checks
icmp_slow = {}
icmp_medium = {}
icmp_rapid = {}
# ICMP dist step 1
icmp_compare_slow = {}
icmp_compare_medium = {}
icmp_compare_rapid = {}
icmp_compare = {}
# ICMP dist step 2
icmp_dist_slow = {}
icmp_dist_medium = {}
icmp_dist_rapid = {}
# ICMP final stats
#Slow
icmp_onetoone_slow = {}
icmp_onetomany_slow = {}
icmp_manytoone_slow = {}
icmp_manytomany_slow = {}
#Medium
icmp_onetoone_medium = {}
icmp_onetomany_medium = {}
icmp_manytoone_medium = {}
icmp_manytomany_medium = {}
#rapid
icmp_onetoone_rapid = {}
icmp_onetomany_rapid = {}
icmp_manytoone_rapid = {}
icmp_manytomany_rapid = {}

# set of ip's
ip_src = set()
tcp_src = set()
udp_src = set()
icmp_src = set()

other = 0

'''
Flows are based on src, dst, dport
Speed based on avrg speed for packets in flow
distrubution are based on speed, flags, src, dst, dport
'''

#for ts, pkt in dpkt.pcap.Reader(open('data/december5_00000_20201230060725.pcap', 'rb')):
#for ts, pkt in dpkt.pcap.Reader(open('data/decmber_packets_00005_20201230060725.pcap', 'rb')):
for ts, pkt in dpkt.pcap.Reader(open('data/decmber5_0__00001_20201230085405.pcap', 'rb')):
#for ts,pkt in dpkt.pcap.Reader(open('data/CaptureOne.pcap','rb')):
    packets += 1
    total_packets += 1 
    eth=dpkt.ethernet.Ethernet(pkt)
    ip = eth.data

    if eth.type==dpkt.ethernet.ETH_TYPE_IP:
        if not socket.inet_ntoa(ip.src).startswith('146.231.254.'):   
            if socket.inet_ntoa(ip.src) not in ip_src:
                ip_src.add(socket.inet_ntoa(ip.src))
            # determine transport layer type
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                # extract IP and transport layer data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                if src_ip not in tcp_src:
                    tcp_src.add(src_ip)


                if isinstance(ip.data, dpkt.tcp.TCP):
                    src_port = ip.data.sport
                    dst_port = ip.data.dport

                    flows = tcp_flows
                    # store flow data
                    flow = ([(src_ip, src_port), (dst_ip, dst_port)])
                    flow = (flow[0], flow[1])

                    if flows.get(flow):
                        flow_data = flows[flow][-1]
                        flow_data['packet_count'] += 1
                        flow_data['SYN_count'] += 1 if ip.data.flags & dpkt.tcp.TH_SYN else 0
                        flow_data['ACK_count'] += 1 if ip.data.flags & dpkt.tcp.TH_ACK else 0
                        flow_data['FIN_count'] += 1 if ip.data.flags & dpkt.tcp.TH_FIN else 0
                        if datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f') < flow_data['first_packet']:
                            flow_data['first_packet'] = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                        if datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f') > flow_data['last_packet']:
                            flow_data['last_packet'] = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                    else:
                        flows[flow] = [{
                            'packet_count': 1,
                            'SYN_count': 1 if ip.data.flags & dpkt.tcp.TH_SYN else 0,
                            'ACK_count': 1 if ip.data.flags & dpkt.tcp.TH_ACK else 0,
                            'FIN_count': 1 if ip.data.flags & dpkt.tcp.TH_FIN else 0,
                            'first_packet': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f'),
                            'last_packet': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                        }]

            elif ip.p == dpkt.ip.IP_PROTO_UDP:

                # extract IP and transport layer data
                src_ip = socket.inet_ntoa(ip.src)
                if src_ip not in udp_src:
                    udp_src.add(src_ip)
                if isinstance (ip.data, dpkt.udp.UDP) and ip.data.sport:
                    src_port = ip.data.dport  
                else:
                    print('no sport udp') 
                dst_ip = socket.inet_ntoa(ip.dst)
                if isinstance (ip.data, dpkt.udp.UDP) and ip.data.dport:
                    dst_port = ip.data.dport  
                else:
                    other += 1 

                flows = udp_flows
                # store flow data
                flow = ([(src_ip, src_port), (dst_ip, dst_port)])
                flow = (flow[0], flow[1])

                if flows.get(flow):
                    flow_data = flows[flow][-1]
                    flow_data['packet_count'] += 1
                    if datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f') < flow_data['first_packet']:
                            flow_data['first_packet'] = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                    if datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f') > flow_data['last_packet']:
                        flow_data['last_packet'] = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                else:
                    flows[flow] = [{
                        'packet_count': 1,
                        'first_packet': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f'),
                        'last_packet': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                    }]
            
            elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                if hasattr(ip, 'icmp'):
                    if hasattr(ip.icmp, 'type'):

                # extract IP and transport layer data
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)
                        if src_ip not in icmp_src:
                            icmp_src.add(src_ip)
                        
                        flows = icmp_flows
                        # store flow data
                        flow = ([(src_ip), (dst_ip)])
                        flow = (flow[0], flow[1])

                        if flows.get(flow):
                            flow_data = flows[flow][-1]
                            flow_data['packet_count'] += 1
                            flow_data['pings'] += 1 if ip.icmp.type == 8 and ip.icmp.code == 0 else 0
                            if datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f') < flow_data['first_packet']:
                                flow_data['first_packet'] = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                            if datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f') > flow_data['last_packet']:
                                flow_data['last_packet'] = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                        else:
                            flows[flow] = [{
                                'packet_count': 1,
                                'pings': 1 if ip.icmp.type == 8 and ip.icmp.code == 0 else 0,
                                'first_packet': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f'),
                                'last_packet': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                            }]
                    else:
                        
                        print('gotcah 2')
                        other += 1
                else:
                    print('gotcah 1')
                    other += 1
    else:
        other += 1
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

print('Starting analysis...')
# Check for tcp distrubution step 1: one-to-one and one-to-many
# TCP
tcp_traffic.tcp_compare_src(tcp_flows, tcp_compare)
print('Traffic TCP compare Done')
udp_traffic.udp_compare_src(udp_flows, udp_compare)
print('Traffic UDP compare Done')
icmp_traffic.icmp_compare_src(icmp_flows, icmp_compare)
print('Traffic compare Done')

# check scanning speed
tcp_traffic.tcp_speed(tcp_compare, tcp_slow, tcp_medium, tcp_rapid)
udp_traffic.udp_speed(udp_compare, udp_slow, udp_medium, udp_rapid)
icmp_traffic.icmp_speed(icmp_compare, icmp_slow, icmp_medium, icmp_rapid)
print('Scanning speed Done')

# check for tcp distrubution step 2: one-to-many and many-to-may
# TCP
tcp_traffic.find_dist(tcp_slow, tcp_dist_slow)
tcp_traffic.find_dist(tcp_medium, tcp_dist_medium)
tcp_traffic.find_dist(tcp_rapid, tcp_dist_rapid)
print('TCP Final dist Done')
# UDP
udp_traffic.find_dist(udp_slow, udp_dist_slow)
udp_traffic.find_dist(udp_medium, udp_dist_medium)
udp_traffic.find_dist(udp_rapid, udp_dist_rapid)
print('UDP Final dist Done')
# ICMP
icmp_traffic.find_dist(icmp_slow, icmp_dist_slow)
icmp_traffic.find_dist(icmp_medium, icmp_dist_medium)
icmp_traffic.find_dist(icmp_rapid, icmp_dist_rapid)
print('Final dist Done')

# put in dict in groups by dist TCP
tcp_traffic.group_dist(tcp_dist_slow, tcp_onetoone_slow, tcp_onetomany_slow, tcp_manytoone_slow, tcp_manytomany_slow)
tcp_traffic.group_dist(tcp_dist_medium, tcp_onetoone_medium, tcp_onetomany_medium, tcp_manytoone_medium, tcp_manytomany_medium)
tcp_traffic.group_dist(tcp_dist_rapid, tcp_onetoone_rapid, tcp_onetomany_rapid, tcp_manytoone_rapid, tcp_manytomany_rapid)
print('TCP Group dist Done')
# put in dict in groups by dist UDP
udp_traffic.group_dist(udp_dist_slow, udp_onetoone_slow, udp_onetomany_slow, udp_manytoone_slow, udp_manytomany_slow)
udp_traffic.group_dist(udp_dist_medium, udp_onetoone_medium, udp_onetomany_medium, udp_manytoone_medium, udp_manytomany_medium)
udp_traffic.group_dist(udp_dist_rapid, udp_onetoone_rapid, udp_onetomany_rapid, udp_manytoone_rapid, udp_manytomany_rapid)
print('UDP Group dist Done')
# put in dict in groups by dist ICMP
icmp_traffic.group_dist(icmp_dist_slow, icmp_onetoone_slow, icmp_onetomany_slow, icmp_manytoone_slow, icmp_manytomany_slow)
icmp_traffic.group_dist(icmp_dist_medium, icmp_onetoone_medium, icmp_onetomany_medium, icmp_manytoone_medium, icmp_manytomany_medium)
icmp_traffic.group_dist(icmp_dist_rapid, icmp_onetoone_rapid, icmp_onetomany_rapid, icmp_manytoone_rapid, icmp_manytomany_rapid)
print('Group dist Done')

# put tcp in flgas dist 
# slow
tcp_traffic.tcp_flags(tcp_onetoone_slow, tcp_oto_slow, tcp_oto_slow_syn, tcp_oto_slow_ack, tcp_oto_slow_fin)
tcp_traffic.tcp_flags(tcp_onetomany_slow, tcp_otm_slow, tcp_otm_slow_syn, tcp_otm_slow_ack, tcp_otm_slow_fin)
tcp_traffic.tcp_flags(tcp_manytoone_slow, tcp_mto_slow, tcp_mto_slow_syn, tcp_mto_slow_ack, tcp_mto_slow_fin)
tcp_traffic.tcp_flags(tcp_manytomany_slow, tcp_mtm_slow, tcp_mtm_slow_syn, tcp_mtm_slow_ack, tcp_mtm_slow_fin)
#medium
tcp_traffic.tcp_flags(tcp_onetoone_medium, tcp_oto_medium, tcp_oto_medium_syn, tcp_oto_medium_ack, tcp_oto_medium_fin)
tcp_traffic.tcp_flags(tcp_onetomany_medium, tcp_otm_medium, tcp_otm_medium_syn, tcp_otm_medium_ack, tcp_otm_medium_fin)
tcp_traffic.tcp_flags(tcp_manytoone_medium, tcp_mto_medium, tcp_mto_medium_syn, tcp_mto_medium_ack, tcp_mto_medium_fin)
tcp_traffic.tcp_flags(tcp_manytomany_medium, tcp_mtm_medium, tcp_mtm_medium_syn, tcp_mtm_medium_ack, tcp_mtm_medium_fin)
# rapid
tcp_traffic.tcp_flags(tcp_onetoone_rapid, tcp_oto_rapid, tcp_oto_rapid_syn, tcp_oto_rapid_ack, tcp_oto_rapid_fin)
tcp_traffic.tcp_flags(tcp_onetomany_rapid, tcp_otm_rapid, tcp_otm_rapid_syn, tcp_otm_rapid_ack, tcp_otm_rapid_fin)
tcp_traffic.tcp_flags(tcp_manytoone_rapid, tcp_mto_rapid, tcp_mto_rapid_syn, tcp_mto_rapid_ack, tcp_mto_rapid_fin)
tcp_traffic.tcp_flags(tcp_manytomany_rapid, tcp_mtm_rapid, tcp_mtm_rapid_syn, tcp_mtm_rapid_ack, tcp_mtm_rapid_fin)

print("---------------------")
print('PCAP info:')
print(f'Number of packets: {total_packets}')
print(f'Total Source IPs: {len(ip_src)}')
print(f'Other traffic: {other}')
print("---------------------")
print("---------------------")
print("TCP")
print(f'Total TCP flows: {len(tcp_flows.keys())}')
print(f'TCP Uniqe IP src: {len(tcp_src)}')
print("---------------------")
print('TCP slow stats')
print(f'Total TCP slow src ips: {sum(val["ip_src_count"] for val in tcp_dist_slow.values())}')
print(f'Total TCP slow one-to-one src ips: {sum(val["ip_src_count"] for val in tcp_onetoone_slow.values())}')
print(f'Total TCP slow one-to-many src ips: {sum(val["ip_src_count"] for val in tcp_onetomany_slow.values())}')
print(f'Total TCP slow many-to-one src ips: {sum(val["ip_src_count"] for val in tcp_manytoone_slow.values())}')
print(f'Total TCP slow many-to-many src ips: {sum(val["ip_src_count"] for val in tcp_manytomany_slow.values())}')
print("---------------------")
#print('slow TCP flows stats:')
#print('slow one-to-one:')
#print(f'TCP one-to-one slow other src ips: {sum(val["ip_src_count"] for val in tcp_oto_slow.values())}')
#print(f'TCP one-to-one slow SYN src ips: {sum(val["ip_src_count"] for val in tcp_oto_slow_syn.values())}')
#print(f'TCP one-to-one slow ACK src ips: {sum(val["ip_src_count"] for val in tcp_oto_slow_ack.values())}')
#print(f'TCP one-to-one slow FIN src ips: {sum(val["ip_src_count"] for val in tcp_oto_slow_fin.values())}')
#print('slow one-to-many:')
#print(f'TCP one-to-many slow other src ips: {sum(val["ip_src_count"] for val in tcp_otm_slow.values())}')
#print(f'TCP one-to-many slow SYN src ips: {sum(val["ip_src_count"] for val in tcp_otm_slow_syn.values())}')
#print(f'TCP one-to-many slow ACK src ips: {sum(val["ip_src_count"] for val in tcp_otm_slow_ack.values())}')
#print(f'TCP one-to-many slow FIN src ips: {sum(val["ip_src_count"] for val in tcp_otm_slow_fin.values())}')
#print('slow many-to-one:')
#print(f'TCP many-to-one slow other src ips: {sum(val["ip_src_count"] for val in tcp_mto_slow.values())}')
#print(f'TCP many-to-one slow SYN src ips: {sum(val["ip_src_count"] for val in tcp_mto_slow_syn.values())}')
#print(f'TCP many-to-one slow ACK src ips: {sum(val["ip_src_count"] for val in tcp_mto_slow_ack.values())}')
#print(f'TCP many-to-one slow FIN src ips: {sum(val["ip_src_count"] for val in tcp_mto_slow_fin.values())}')
#print('slow many-to-many:')
#print(f'TCP many-to-many slow other src ips: {sum(val["ip_src_count"] for val in tcp_mtm_slow.values())}')
#print(f'TCP many-to-many slow SYN src ips: {sum(val["ip_src_count"] for val in tcp_mtm_slow_syn.values())}')
#print(f'TCP many-to-many slow ACK src ips: {sum(val["ip_src_count"] for val in tcp_mtm_slow_ack.values())}')
#print(f'TCP many-to-many slow FIN src ips: {sum(val["ip_src_count"] for val in tcp_mtm_slow_fin.values())}')
print("---------------------")
print('TCP medium stats')
print(f'Total tcp medium src ips: {sum(val["ip_src_count"] for val in tcp_dist_medium.values())}')
print(f'Total tcp medium one-to-one src ips: {sum(val["ip_src_count"] for val in tcp_onetoone_medium.values())}')
print(f'Total tcp medium one-to-many src ips: {sum(val["ip_src_count"] for val in tcp_onetomany_medium.values())}')
print(f'Total tcp medium many-to-one src ips: {sum(val["ip_src_count"] for val in tcp_manytoone_medium.values())}')
print(f'Total tcp medium many-to-many src ips: {sum(val["ip_src_count"] for val in tcp_manytomany_medium.values())}')
print("---------------------")
#print('medium TCP flows stats:')
#print('medium one-to-one:')
#print(f'TCP one-to-one medium other src ips: {sum(val["ip_src_count"] for val in tcp_oto_medium.values())}')
#print(f'TCP one-to-one medium SYN src ips: {sum(val["ip_src_count"] for val in tcp_oto_medium_syn.values())}')
#print(f'TCP one-to-one medium ACK src ips: {sum(val["ip_src_count"] for val in tcp_oto_medium_ack.values())}')
#print(f'TCP one-to-one medium FIN src ips: {sum(val["ip_src_count"] for val in tcp_oto_medium_fin.values())}')
#print('medium one-to-many:')
#print(f'TCP one-to-many medium other src ips: {sum(val["ip_src_count"] for val in tcp_otm_medium.values())}')
#print(f'TCP one-to-many medium SYN src ips: {sum(val["ip_src_count"] for val in tcp_otm_medium_syn.values())}')
#print(f'TCP one-to-many medium ACK src ips: {sum(val["ip_src_count"] for val in tcp_otm_medium_ack.values())}')
#print(f'TCP one-to-many medium FIN src ips: {sum(val["ip_src_count"] for val in tcp_otm_medium_fin.values())}')
#print('medium many-to-one:')
#print(f'TCP many-to-one medium other src ips: {sum(val["ip_src_count"] for val in tcp_mto_medium.values())}')
#print(f'TCP many-to-one medium SYN src ips: {sum(val["ip_src_count"] for val in tcp_mto_medium_syn.values())}')
#print(f'TCP many-to-one medium ACK src ips: {sum(val["ip_src_count"] for val in tcp_mto_medium_ack.values())}')
#print(f'TCP many-to-one medium FIN src ips: {sum(val["ip_src_count"] for val in tcp_mto_medium_fin.values())}')
#print('medium many-to-many:')
#print(f'TCP many-to-many medium other src ips: {sum(val["ip_src_count"] for val in tcp_mtm_medium.values())}')
#print(f'TCP many-to-many medium SYN src ips: {sum(val["ip_src_count"] for val in tcp_mtm_medium_syn.values())}')
#print(f'TCP many-to-many medium ACK src ips: {sum(val["ip_src_count"] for val in tcp_mtm_medium_ack.values())}')
#print(f'TCP many-to-many medium FIN src ips: {sum(val["ip_src_count"] for val in tcp_mtm_medium_fin.values())}')
print("---------------------")
print('TCP Rapid stats')
print(f'Total tcp rapid src ips: {sum(val["ip_src_count"] for val in tcp_dist_rapid.values())}')
print(f'Total tcp rapid one-to-one src ips: {sum(val["ip_src_count"] for val in tcp_onetoone_rapid.values())}')
print(f'Total tcp rapid one-to-many src ips: {sum(val["ip_src_count"] for val in tcp_onetomany_rapid.values())}')
print(f'Total tcp rapid many-to-one src ips: {sum(val["ip_src_count"] for val in tcp_manytoone_rapid.values())}')
print(f'Total tcp rapid many-to-many src ips: {sum(val["ip_src_count"] for val in tcp_manytomany_rapid.values())}')
print("---------------------")
#print('Rapid TCP flows stats:')
#print('rapid one-to-one:')
#print(f'TCP one-to-one rapid other src ips: {sum(val["ip_src_count"] for val in tcp_oto_rapid.values())}')
#print(f'TCP one-to-one rapid SYN src ips: {sum(val["ip_src_count"] for val in tcp_oto_rapid_syn.values())}')
#print(f'TCP one-to-one rapid ACK src ips: {sum(val["ip_src_count"] for val in tcp_oto_rapid_ack.values())}')
#print(f'TCP one-to-one rapid FIN src ips: {sum(val["ip_src_count"] for val in tcp_oto_rapid_fin.values())}')
#print('rapid one-to-many:')
#print(f'TCP one-to-many rapid other src ips: {sum(val["ip_src_count"] for val in tcp_otm_rapid.values())}')
#print(f'TCP one-to-many rapid SYN src ips: {sum(val["ip_src_count"] for val in tcp_otm_rapid_syn.values())}')
#print(f'TCP one-to-many rapid ACK src ips: {sum(val["ip_src_count"] for val in tcp_otm_rapid_ack.values())}')
#print(f'TCP one-to-many rapid FIN src ips: {sum(val["ip_src_count"] for val in tcp_otm_rapid_fin.values())}')
#print('rapid many-to-one:')
#print(f'TCP many-to-one rapid other src ips: {sum(val["ip_src_count"] for val in tcp_mto_rapid.values())}')
#print(f'TCP many-to-one rapid SYN src ips: {sum(val["ip_src_count"] for val in tcp_mto_rapid_syn.values())}')
#print(f'TCP many-to-one rapid ACK src ips: {sum(val["ip_src_count"] for val in tcp_mto_rapid_ack.values())}')
#print(f'TCP many-to-one rapid FIN src ips: {sum(val["ip_src_count"] for val in tcp_mto_rapid_fin.values())}')
#print('rapid many-to-many:')
#print(f'TCP many-to-many rapid other src ips: {sum(val["ip_src_count"] for val in tcp_mtm_rapid.values())}')
#print(f'TCP many-to-many rapid SYN src ips: {sum(val["ip_src_count"] for val in tcp_mtm_rapid_syn.values())}')
#print(f'TCP many-to-many rapid ACK src ips: {sum(val["ip_src_count"] for val in tcp_mtm_rapid_ack.values())}')
#print(f'TCP many-to-many rapid FIN src ips: {sum(val["ip_src_count"] for val in tcp_mtm_rapid_fin.values())}')
print("---------------------")
print("---------------------")
print("UDP")
print(f'Total UDP flows: {len(udp_flows.keys())}')
print(f'UDP Uniqe IP src: {len(udp_src)}')
print("---------------------")
print('UDP slow stats')
print(f'Total udp slow src ips: {sum(val["ip_src_count"] for val in udp_dist_slow.values())}')
print(f'Total udp slow one-to-one src ips: {sum(val["ip_src_count"] for val in udp_onetoone_slow.values())}')
print(f'Total udp slow one-to-many src ips: {sum(val["ip_src_count"] for val in udp_onetomany_slow.values())}')
print(f'Total udp slow many-to-one src ips: {sum(val["ip_src_count"] for val in udp_manytoone_slow.values())}')
print(f'Total udp slow many-to-many src ips: {sum(val["ip_src_count"] for val in udp_manytomany_slow.values())}')
print("---------------------")
print('UDP Medium stats')
print(f'Total udp medium src ips: {sum(val["ip_src_count"] for val in udp_dist_medium.values())}')
print(f'Total udp medium one-to-one src ips: {sum(val["ip_src_count"] for val in udp_onetoone_medium.values())}')
print(f'Total udp medium one-to-many src ips: {sum(val["ip_src_count"] for val in udp_onetomany_medium.values())}')
print(f'Total udp medium many-to-one src ips: {sum(val["ip_src_count"] for val in udp_manytoone_medium.values())}')
print(f'Total udp medium many-to-many src ips: {sum(val["ip_src_count"] for val in udp_manytomany_medium.values())}')
print("---------------------")
print('UDP Rapid stats')
print(f'Total udp rapid src ips: {sum(val["ip_src_count"] for val in udp_dist_rapid.values())}')
print(f'Total udp rapid one-to-one src ips: {sum(val["ip_src_count"] for val in udp_onetoone_rapid.values())}')
print(f'Total udp rapid one-to-many src ips: {sum(val["ip_src_count"] for val in udp_onetomany_rapid.values())}')
print(f'Total udp rapid many-to-one src ips: {sum(val["ip_src_count"] for val in udp_manytoone_rapid.values())}')
print(f'Total udp rapid many-to-many src ips: {sum(val["ip_src_count"] for val in udp_manytomany_rapid.values())}')
print("---------------------")
print("---------------------")
print("ICMP")
print(f'Total ICMP flows: {len(icmp_flows.keys())}')
print(f'ICMP Uniqe IP src: {len(icmp_src)}')
print("---------------------")
print('ICMP slow stats')
print(f'Total icmp slow src ips: {sum(val["ip_src_count"] for val in icmp_dist_slow.values())}')
print(f'Total icmp slow one-to-one src ips: {sum(val["ip_src_count"] for val in icmp_onetoone_slow.values())}')
print(f'Total icmp slow one-to-many src ips: {sum(val["ip_src_count"] for val in icmp_onetomany_slow.values())}')
print(f'Total icmp slow many-to-one src ips: {sum(val["ip_src_count"] for val in icmp_manytoone_slow.values())}')
print(f'Total icmp slow many-to-many src ips: {sum(val["ip_src_count"] for val in icmp_manytomany_slow.values())}')
print("---------------------")
print('ICMP Medium stats')
print(f'Total icmp medium src ips: {sum(val["ip_src_count"] for val in icmp_dist_medium.values())}')
print(f'Total icmp medium one-to-one src ips: {sum(val["ip_src_count"] for val in icmp_onetoone_medium.values())}')
print(f'Total icmp medium one-to-many src ips: {sum(val["ip_src_count"] for val in icmp_onetomany_medium.values())}')
print(f'Total icmp medium many-to-one src ips: {sum(val["ip_src_count"] for val in icmp_manytoone_medium.values())}')
print(f'Total icmp medium many-to-many src ips: {sum(val["ip_src_count"] for val in icmp_manytomany_medium.values())}')
print("---------------------")
print('ICMP Rapid stats')
print(f'Total icmp rapid src ips: {sum(val["ip_src_count"] for val in icmp_dist_rapid.values())}')
print(f'Total icmp rapid one-to-one src ips: {sum(val["ip_src_count"] for val in icmp_onetoone_rapid.values())}')
print(f'Total icmp rapid one-to-many src ips: {sum(val["ip_src_count"] for val in icmp_onetomany_rapid.values())}')
print(f'Total icmp rapid many-to-one src ips: {sum(val["ip_src_count"] for val in icmp_manytoone_rapid.values())}')
print(f'Total icmp rapid many-to-many src ips: {sum(val["ip_src_count"] for val in icmp_manytomany_rapid.values())}')
print("---------------------")
print(f'Other traffic: {other}')
print("---------------------")


#for val in tcp_manytoone_rapid.values():
 #   if val['ip_src_count'] < val['packet_count']:
  #      print(val['packet_count'])


for key, val in tcp_manytoone_rapid.items():
    if sum(len(port_range) for port_range in val['dst_ports']) > 1:
        print(key) 

for key, val in udp_manytoone_rapid.items():
    if sum(len(port_range) for port_range in val['dst_ports']) > 1:
        print(key)

for key, val in tcp_manytomany_rapid.items():
    if sum(len(port_range) for port_range in val['dst_ports']) > 1:
        print(key) 

for key, val in udp_manytomany_rapid.items():
    if sum(len(port_range) for port_range in val['dst_ports']) > 1:
        print(key)

# Print out values and count for one-to-many
for key, value in tcp_onetomany_slow.items():
    if '51.255.81.155' in value['src_ips']:
        print(len(key), sum(len(port_range) for port_range in value['dst_ports']), value['src_ips'], value['packet_count'])

print(' check for 193.122.96.137 ')
for key, value in tcp_onetoone_slow.items():
    if '193.122.96.137' in value['src_ips']:
        print(len(key), sum(len(port_range) for port_range in value['dst_ports']), value['src_ips'], value['packet_count'])
for key, value in tcp_onetoone_medium.items():
    if '193.122.96.137' in value['src_ips']:
        print(len(key), sum(len(port_range) for port_range in value['dst_ports']), value['src_ips'], value['packet_count'])
for key, value in tcp_onetoone_rapid.items():
    if '193.122.96.137' in value['src_ips']:
        print(len(key), sum(len(port_range) for port_range in value['dst_ports']), value['src_ips'], value['packet_count'])

#with open('tcp_many-ports-check_barnett.txt', 'w') as f:
    #f.write(f'Total TCP slow one-to-one src ips: {tcp_onetoone_rapid}\n')
  #  f.write("---------------------\n")
   # f.write(f'Total TCP slow one-to-many src ips: {tcp_onetomany_rapid}\n')
    #f.write("---------------------\n")
 #   f.write(f'Total TCP slow many-to-one src ips: {tcp_manytoone_rapid}\n')
    #f.write("---------------------\n")
  #  f.write(f'Total TCP slow many-to-many src ips: {tcp_manytomany_rapid}\n')

