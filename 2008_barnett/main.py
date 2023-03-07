import dpkt
from functools import reduce
import socket
from datetime import datetime

tcp_flows = {}
udp_flows = {}
icmp_flows = {}
ips = set()

for ts,pkt in dpkt.pcap.Reader(open('data/CaptureOne.pcap','rb')):
    eth=dpkt.ethernet.Ethernet(pkt)
    ip = eth.data

    if ip.p == 1:
        pass

    elif eth.type==dpkt.ethernet.ETH_TYPE_IP:   
        
        # extract IP and transport layer data
        src_ip = socket.inet_ntoa(ip.src)
        src_port = ip.data.sport
        dst_ip = socket.inet_ntoa(ip.dst)
        dst_port = ip.data.dport

        # keeping set of unique IPs
        ips.add(src_ip)
        ips.add(dst_ip)

        # determine transport layer type
        if ip.p == dpkt.ip.IP_PROTO_TCP:
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
            flows = icmp_flows
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

        

print(f'Total TCP flows: {tcp_flows}')
print(f'Total TCP flows: {len(tcp_flows.keys())}')
print(f'Total UDP flows: {len(udp_flows.keys())}')
print(f'Total ICMP flows: {len(icmp_flows.keys())}')
print(f'Total IPs: {len(ips)}')
