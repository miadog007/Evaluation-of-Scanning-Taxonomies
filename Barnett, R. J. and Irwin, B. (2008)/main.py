import dpkt
from functools import reduce
import socket
from datetime import datetime
import time
from flows import tcp_traffic, udp_traffic, icmp_traffic


# Counter fro number of packets and number of minutes
# Packets reset every minute
packets = 0
minutes = 0
start_time = time.time()

# Counter for number of packets in Packet Capture
total_packets = 0

# --------------------------------------------------- 
# TCP flows
tcp_flows = {}

# tcp dist step 1
tcp_compare = {}

# tcp speed checks
tcp_slow, tcp_medium, tcp_rapid = ({} for i in range(3))

# tcp dist step 2
tcp_dist_slow, tcp_dist_medium, tcp_dist_rapid = ({} for i in range(3))

# TCP One-to-One dicts fro Slow, Medium and Rapid
tcp_onetoone_slow, tcp_onetoone_medium, tcp_onetoone_rapid = ({} for i in range(3))

# tcp one-to-many dicts for Slow, Medium and Rapid
tcp_onetomany_slow, tcp_onetomany_medium, tcp_onetomany_rapid = ({} for i in range(3))

# tcp many-to-one dicts for Slow, Medium and Rapid
tcp_manytoone_slow, tcp_manytoone_medium, tcp_manytoone_rapid = ({} for i in range(3))

# tcp many-to-many dicts for Slow, Medium and Rapid
tcp_manytomany_slow, tcp_manytomany_medium, tcp_manytomany_rapid = ({} for i in range(3))

# tcp Slow one-to-one with flags
tcp_oto_slow, tcp_oto_slow_syn, tcp_oto_slow_ack, tcp_oto_slow_fin = ({} for i in range(4))

# tcp Medium one-to-one with flags
tcp_oto_medium, tcp_oto_medium_syn, tcp_oto_medium_ack, tcp_oto_medium_fin = ({} for i in range(4))

# tcp Rapid one-to-one with flags
tcp_oto_rapid, tcp_oto_rapid_syn, tcp_oto_rapid_ack, tcp_oto_rapid_fin = ({} for i in range(4))

# tcp Slow one-to-many with flags
tcp_otm_slow, tcp_otm_slow_syn, tcp_otm_slow_ack, tcp_otm_slow_fin = ({} for i in range(4))

# tcp Medium one-to-many with flags
tcp_otm_medium, tcp_otm_medium_syn, tcp_otm_medium_ack, tcp_otm_medium_fin = ({} for i in range(4))

# tcp Rapid one-to-many with flags
tcp_otm_rapid, tcp_otm_rapid_syn, tcp_otm_rapid_ack, tcp_otm_rapid_fin = ({} for i in range(4))

# tcp Slow many-to-one with flags
tcp_mto_slow, tcp_mto_slow_syn, tcp_mto_slow_ack, tcp_mto_slow_fin = ({} for i in range(4))

# tcp Medium many-to-one with flags
tcp_mto_medium, tcp_mto_medium_syn, tcp_mto_medium_ack, tcp_mto_medium_fin = ({} for i in range(4))

# tcp Rapid many-to-one with flags
tcp_mto_rapid, tcp_mto_rapid_syn, tcp_mto_rapid_ack, tcp_mto_rapid_fin = ({} for i in range(4))

# tcp Slow many-to-many with flags
tcp_mtm_slow, tcp_mtm_slow_syn, tcp_mtm_slow_ack, tcp_mtm_slow_fin = ({} for i in range(4))

# tcp Medium many-to-many with flags
tcp_mtm_medium, tcp_mtm_medium_syn, tcp_mtm_medium_ack, tcp_mtm_medium_fin = ({} for i in range(4))

# tcp Rapid many-to-many with flags
tcp_mtm_rapid, tcp_mtm_rapid_syn, tcp_mtm_rapid_ack, tcp_mtm_rapid_fin = ({} for i in range(4))

# --------------------------------------------------- 
# udp flows
udp_flows = {}

# udp dist step 1
udp_compare = {}

# udp speed checks
udp_slow, udp_medium, udp_rapid = ({} for i in range(3))

# udp dist step 2
udp_dist_slow, udp_dist_medium, udp_dist_rapid = ({} for i in range(3))

# udp One-to-One dicts fro Slow, Medium and Rapid
udp_onetoone_slow, udp_onetoone_medium, udp_onetoone_rapid = ({} for i in range(3))

# udp one-to-many dicts for Slow, Medium and Rapid
udp_onetomany_slow, udp_onetomany_medium, udp_onetomany_rapid = ({} for i in range(3))

# udp many-to-one dicts for Slow, Medium and Rapid
udp_manytoone_slow, udp_manytoone_medium, udp_manytoone_rapid = ({} for i in range(3))

# udp many-to-many dicts for Slow, Medium and Rapid
udp_manytomany_slow, udp_manytomany_medium, udp_manytomany_rapid = ({} for i in range(3))

# --------------------------------------------------- 
# icmp flows
icmp_flows = {}

# icmp dist step 1
icmp_compare = {}

# icmp speed checks
icmp_slow, icmp_medium, icmp_rapid = ({} for i in range(3))

# icmp dist step 2
icmp_dist_slow, icmp_dist_medium, icmp_dist_rapid = ({} for i in range(3))

# icmp One-to-One dicts fro Slow, Medium and Rapid
icmp_onetoone_slow, icmp_onetoone_medium, icmp_onetoone_rapid = ({} for i in range(3))

# icmp one-to-many dicts for Slow, Medium and Rapid
icmp_onetomany_slow, icmp_onetomany_medium, icmp_onetomany_rapid = ({} for i in range(3))

# icmp many-to-one dicts for Slow, Medium and Rapid
icmp_manytoone_slow, icmp_manytoone_medium, icmp_manytoone_rapid = ({} for i in range(3))

# icmp many-to-many dicts for Slow, Medium and Rapid
icmp_manytomany_slow, icmp_manytomany_medium, icmp_manytomany_rapid = ({} for i in range(3))

# set of ip's
ip_src = set()
tcp_src = set()
udp_src = set()
icmp_src = set()

# Count for "Other" Traffic
other = 0

# Insert Packet Capture
pcap = ''

# Main functions for finding TCP, UDP or ICMP packets
for ts, pkt in dpkt.pcap.Reader(open(pcap, 'rb')):
    '''
    Flows are based on src, dst, dport
    Speed based on avrg speed for packets in flow
    distrubution are based on speed, flags, src, dst, dport
    '''
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
            if src_ip not in tcp_src:
                tcp_src.add(src_ip)


            if isinstance(ip.data, dpkt.tcp.TCP):
                src_port = ip.data.sport
                dst_port = ip.data.dport

                flows = tcp_flows
                # store flow data
                flow = ([(src_ip, src_port), (dst_ip, dst_port)])
                flow = (flow[0], flow[1])

                # Update count SYN, ACK and FIN flags
                if flows.get(flow):
                    flow_data = flows[flow][-1]
                    flow_data['packet_count'] += 1
                    flow_data['SYN_count'] += 1 if ip.data.flags & dpkt.tcp.TH_SYN else 0
                    flow_data['ACK_count'] += 1 if ip.data.flags & dpkt.tcp.TH_ACK else 0
                    flow_data['FIN_count'] += 1 if ip.data.flags & dpkt.tcp.TH_FIN else 0

                    # Update first and last packet in flow
                    if datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f') < flow_data['first_packet']:
                        flow_data['first_packet'] = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                    if datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f') > flow_data['last_packet']:
                        flow_data['last_packet'] = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                else:
                    flows[flow] = [{
                        'packet_count': 1,
                        # Count SYN, ACK and FIN flags in flow
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
                dst_ip = socket.inet_ntoa(ip.dst)
                if isinstance (ip.data, dpkt.udp.UDP) and ip.data.dport:
                    dst_port = ip.data.dport  
                    flows = udp_flows
                    # store flow data
                    flow = ([(src_ip, src_port), (dst_ip, dst_port)])
                    flow = (flow[0], flow[1])

                    if flows.get(flow):
                        flow_data = flows[flow][-1]
                        flow_data['packet_count'] += 1

                        # Update first and last packet in flow
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
                else:
                    other += 1 
            else:
                other += 1 
        elif ip.p == dpkt.ip.IP_PROTO_ICMP:

            # Extra checks for ICMP
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

                        # Update count pings
                        flow_data['pings'] += 1 if ip.icmp.type == 8 and ip.icmp.code == 0 else 0

                        # Update first and last packet in flow
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
                    other += 1
            else:
                other += 1
        else:
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


tcp_packets = (sum(val["packet_count"] for val in tcp_dist_slow.values()) + 
                  sum(val["packet_count"] for val in tcp_dist_medium.values())+
                  sum(val["packet_count"] for val in tcp_dist_rapid.values()))

udp_packets = (sum(val["packet_count"] for val in udp_dist_slow.values())+
                  sum(val["packet_count"] for val in udp_dist_medium.values())+
                  sum(val["packet_count"] for val in udp_dist_rapid.values()))

icmp_packets = (sum(val["packet_count"] for val in icmp_dist_slow.values())+
                  sum(val["packet_count"] for val in icmp_dist_medium.values())+
                  sum(val["packet_count"] for val in icmp_dist_rapid.values()))


# Printing out result of each category in Barnett & Irwin 2008
print("---------------------")
print('PCAP info:')
print(f'PCAP file: {pcap}')
print(f'Number of packets: {total_packets}')
print(f'Uncategorized Packets(Other): {other}')
print(f'Total Source IPs: {len(ip_src)}')
print("---------------------")
print("---------------------")
print("TCP")
print(f'Total TCP flows: {len(tcp_flows.keys())}')
print(f'TCP packets: {tcp_packets}')
print("---------------------")
print('TCP slow stats')
print(f'Total TCP slow packets: {sum(val["packet_count"] for val in tcp_dist_slow.values())}')
print(f'Total TCP slow one-to-one packets: {sum(val["packet_count"] for val in tcp_onetoone_slow.values())}')
print(f'Total TCP slow one-to-many packets: {sum(val["packet_count"] for val in tcp_onetomany_slow.values())}')
print(f'Total TCP slow many-to-one packets: {sum(val["packet_count"] for val in tcp_manytoone_slow.values())}')
print(f'Total TCP slow many-to-many packets: {sum(val["packet_count"] for val in tcp_manytomany_slow.values())}')
print("---------------------")
print("---------------------")
print('TCP medium stats')
print(f'Total tcp medium packets: {sum(val["packet_count"] for val in tcp_dist_medium.values())}')
print(f'Total tcp medium one-to-one packets: {sum(val["packet_count"] for val in tcp_onetoone_medium.values())}')
print(f'Total tcp medium one-to-many packets: {sum(val["packet_count"] for val in tcp_onetomany_medium.values())}')
print(f'Total tcp medium many-to-one packets: {sum(val["packet_count"] for val in tcp_manytoone_medium.values())}')
print(f'Total tcp medium many-to-many packets: {sum(val["packet_count"] for val in tcp_manytomany_medium.values())}')
print("---------------------")
print("---------------------")
print('TCP Rapid stats')
print(f'Total tcp rapid packets: {sum(val["packet_count"] for val in tcp_dist_rapid.values())}')
print(f'Total tcp rapid one-to-one packets: {sum(val["packet_count"] for val in tcp_onetoone_rapid.values())}')
print(f'Total tcp rapid one-to-many packets: {sum(val["packet_count"] for val in tcp_onetomany_rapid.values())}')
print(f'Total tcp rapid many-to-one packets: {sum(val["packet_count"] for val in tcp_manytoone_rapid.values())}')
print(f'Total tcp rapid many-to-many packets: {sum(val["packet_count"] for val in tcp_manytomany_rapid.values())}')
print("---------------------")
print("---------------------")
print("---------------------")
print("UDP")
print(f'Total UDP flows: {len(udp_flows.keys())}')
print(f'UDP packets: {udp_packets}')
print("---------------------")
print('UDP slow stats')
print(f'Total UDP slow packets: {sum(val["packet_count"] for val in udp_dist_slow.values())}')
print(f'Total UDP slow one-to-one packets: {sum(val["packet_count"] for val in udp_onetoone_slow.values())}')
print(f'Total UDP slow one-to-many packets: {sum(val["packet_count"] for val in udp_onetomany_slow.values())}')
print(f'Total UDP slow many-to-one packets: {sum(val["packet_count"] for val in udp_manytoone_slow.values())}')
print(f'Total UDP slow many-to-many packets: {sum(val["packet_count"] for val in udp_manytomany_slow.values())}')
print("---------------------")
print('UDP Medium stats')
print(f'Total UDP medium packets: {sum(val["packet_count"] for val in udp_dist_medium.values())}')
print(f'Total UDP medium one-to-one packets: {sum(val["packet_count"] for val in udp_onetoone_medium.values())}')
print(f'Total UDP medium one-to-many packets: {sum(val["packet_count"] for val in udp_onetomany_medium.values())}')
print(f'Total UDP medium many-to-one packets: {sum(val["packet_count"] for val in udp_manytoone_medium.values())}')
print(f'Total UDP medium many-to-many packets: {sum(val["packet_count"] for val in udp_manytomany_medium.values())}')
print("---------------------")
print('UDP Rapid stats')
print(f'Total UDP rapid packets: {sum(val["packet_count"] for val in udp_dist_rapid.values())}')
print(f'Total UDP rapid one-to-one packets: {sum(val["packet_count"] for val in udp_onetoone_rapid.values())}')
print(f'Total UDP rapid one-to-many packets: {sum(val["packet_count"] for val in udp_onetomany_rapid.values())}')
print(f'Total UDP rapid many-to-one packets: {sum(val["packet_count"] for val in udp_manytoone_rapid.values())}')
print(f'Total UDP rapid many-to-many packets: {sum(val["packet_count"] for val in udp_manytomany_rapid.values())}')
print("---------------------")
print("---------------------")
print("ICMP")
print(f'Total ICMP flows: {len(icmp_flows.keys())}')
print(f'ICMP packets: {icmp_packets}')
print("---------------------")
print('ICMP slow stats')
print(f'Total ICMP slow packets: {sum(val["packet_count"] for val in icmp_dist_slow.values())}')
print(f'Total ICMP slow one-to-one packets: {sum(val["packet_count"] for val in icmp_onetoone_slow.values())}')
print(f'Total ICMP slow one-to-many packets: {sum(val["packet_count"] for val in icmp_onetomany_slow.values())}')
print(f'Total ICMP slow many-to-one packets: {sum(val["packet_count"] for val in icmp_manytoone_slow.values())}')
print(f'Total ICMP slow many-to-many packets: {sum(val["packet_count"] for val in icmp_manytomany_slow.values())}')
print("---------------------")
print('ICMP Medium stats')
print(f'Total ICMP medium packets: {sum(val["packet_count"] for val in icmp_dist_medium.values())}')
print(f'Total ICMP medium one-to-one packets: {sum(val["packet_count"] for val in icmp_onetoone_medium.values())}')
print(f'Total ICMP medium one-to-many packets: {sum(val["packet_count"] for val in icmp_onetomany_medium.values())}')
print(f'Total ICMP medium many-to-one packets: {sum(val["packet_count"] for val in icmp_manytoone_medium.values())}')
print(f'Total ICMP medium many-to-many packets: {sum(val["packet_count"] for val in icmp_manytomany_medium.values())}')
print("---------------------")
print('ICMP Rapid stats')
print(f'Total ICMP rapid packets: {sum(val["packet_count"] for val in icmp_dist_rapid.values())}')
print(f'Total ICMP rapid one-to-one packets: {sum(val["packet_count"] for val in icmp_onetoone_rapid.values())}')
print(f'Total ICMP rapid one-to-many packets: {sum(val["packet_count"] for val in icmp_onetomany_rapid.values())}')
print(f'Total ICMP rapid many-to-one packets: {sum(val["packet_count"] for val in icmp_manytoone_rapid.values())}')
print(f'Total ICMP rapid many-to-many packets: {sum(val["packet_count"] for val in icmp_manytomany_rapid.values())}')
print("---------------------")
