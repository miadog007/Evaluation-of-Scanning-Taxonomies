import dpkt
from functools import reduce
import socket

tcp_flows = {}
udp_flows = {}
icmp_flows = {}
ips = set()

def dumpFlow(flows, flow):
    print(f'Data for flow: {flow}:')
    bytes = reduce(lambda x, y: x+y,
                   map(lambda e: e['byte_count'], flows[flow]))
    duration = sorted(map(lambda e: e['ts'], flows[flow]))
    duration = duration[-1] - duration[0]
    print(f"\tTotal Bytes: {bytes}")
    print(f"\tAverage Bytes: {bytes / len(flows[flow])}")
    print(f"\tTotal Duration: {duration}")
    print("\tPackets:")
    for packet in flows[flow]:
        hex_packet = ' '.join([f'\\x{byte:02x}' for byte in packet['raw']])
        print(f"\t\t{hex_packet}")


for ts,pkt in dpkt.pcap.Reader(open('data/CaptureOne.pcap','rb')):
    eth=dpkt.ethernet.Ethernet(pkt)
    ip = eth.data

    if ip.p == 1:
        pass

    elif eth.type==dpkt.ethernet.ETH_TYPE_IP:


        # determine transport layer type
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            flows = tcp_flows
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            flows = udp_flows
        elif ip.p == dpkt.ip.IP_PROTO_ICMP:
            flows = icmp_flows

        # extract IP and transport layer data
        src_ip = socket.inet_ntoa(ip.src)
        src_port = ip.data.sport
        dst_ip = socket.inet_ntoa(ip.dst)
        dst_port = ip.data.dport

        # keeping set of unique IPs
        ips.add(src_ip)
        ips.add(dst_ip)

        # store flow data
        flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        flow = (flow[0], flow[1])
        flow_data = {
            'ts': ts,
            'data': pkt,
        }

        if flows.get(flow):
            flows[flow].append(flow_data)
        else:
            flows[flow] = [flow_data]




print(f'Total TCP flows: {len(tcp_flows.keys())}')
print(f'Total UDP flows: {len(udp_flows.keys())}')
print(f'Total ICMP flows: {len(icmp_flows.keys())}')
print(f'Total IPs: {len(ips)}')

#for k in tcp_flows.keys():
 #   dumpFlow(tcp_flows, k)
#for k in udp_flows.keys():
 #   dumpFlow(udp_flows, k)
