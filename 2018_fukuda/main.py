import dpkt
import socket
from flows import tcp_traffic


other = 0

# dict for tcp flows and tcp_src
tcp_flows = {}
tcp_srcs = {}


for ts, pkt in dpkt.pcap.Reader(open('data/CaptureOne.pcap', 'rb')):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data

    # Find protocole  
    if isinstance(ip, dpkt.ip.IP):
        # Find TCP
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            dst_port = ip.data.dport
            # send to tcp_sinle_flow
            tcp_flow = tcp_traffic.tcp_single_flow(pkt, src_ip, dst_ip, tcp_flows)
            if tcp_flow is not None:
                tcp_flows[(src_ip, dst_ip)] = tcp_flow
            # Send to tcp_single_src
            tcp_src = tcp_traffic.tcp_single_src(pkt, src_ip, dst_port, tcp_srcs)
            if tcp_src is not None:
               tcp_srcs[(src_ip, dst_port)] = tcp_src

        # Find UDP
    elif isinstance(ip, dpkt.ip.IP):
        if ip.p == dpkt.ip.IP_PROTO_UDP:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            print('hello')
        # Find ICMP
    elif isinstance(ip, dpkt.ip.IP):
        if ip.p == dpkt.ip.IP_PROTO_ICMP:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            print('hello2')
    else:
        other += 1

        
for flow_key, flow in tcp_flows.items():
    print(f"Flow: {flow_key[0]}->{flow_key[1]}")
    print(f"Packets: {flow['num_packets']}")
    print(f"Scan Percentage: {flow['scan_percent']}%")
    print(f"Syn Percentage: {flow['syn_percent']}%")
    print(f"Frag Percentage: {flow['frag_percent']}%")
    print(f"Packets per port: {flow['avg_packets_per_dst_port']}")


print(tcp_srcs)
print(other)
        