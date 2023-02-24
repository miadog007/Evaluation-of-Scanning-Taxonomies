import dpkt
import socket

'''
This script find the category "O
'''

tflows = {}
uflows = {}

N3 = 15

for ts, pkt in dpkt.pcap.Reader(open('data/CaptureOne.pcap', 'rb')):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data

    # determine transport layer type
    if isinstance(ip, dpkt.ip.IP):
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            flows = tflows
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            flows = uflows
        else:
            flows = {}

        # extract IP and transport layer data
        src_ip = socket.inet_ntoa(ip.src)
        src_port = ip.data.sport
        dst_ip = socket.inet_ntoa(ip.dst)
        dst_port = ip.data.dport

        # store flow data
        flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        flow = (flow[0], flow[1])
        flow_data = {
            'byte_count': len(eth),
            'ts': ts
        }

        if flows.get(flow):
            flows[flow].append(flow_data)
        else:
            flows[flow] = [flow_data]

def print_flow_info(proto, src_ip, dst_ip, dst_port, packets):
    print(f'Flow Info: {proto} {src_ip} -> {dst_ip}:{dst_port}')
    print(f'\tNumber of packets: {packets}')
    print('')

seen_flows = set()

for flow, packets in tflows.items():
    proto = 'TCP'
    src_ip = flow[0][0]
    dst_ip = flow[1][0]
    dst_port = flow[1][1]
    packets_per_flow = len(packets)

    if (proto, src_ip, dst_ip, dst_port) in seen_flows:
        continue

    if packets_per_flow > N3:
        print_flow_info(proto, src_ip, dst_ip, dst_port, packets_per_flow)
        seen_flows.add((proto, src_ip, dst_ip, dst_port))

for flow, packets in uflows.items():
    proto = 'UDP'
    src_ip = flow[0][0]
    dst_ip = flow[1][0]
    dst_port = flow[1][1]
    packets_per_flow = len(packets)

    if (proto, src_ip, dst_ip, dst_port) in seen_flows:
        continue

    if packets_per_flow > N3:
        print_flow_info(proto, src_ip, dst_ip, dst_port, packets_per_flow)
        seen_flows.add((proto, src_ip, dst_ip, dst_port))
