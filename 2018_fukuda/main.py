import dpkt
import socket
from flows import tcp_traffic
from anlysis import tcp_analysis

other = 0

# dict for tcp traffic
tcp_flows = {}
tcp_srcs = {}
tcp_one_flows = {}
tcp_backscatters = {}
small_syns = {}
other_tcp = 0

# dict for UDP traffic
udp_flows = {}
udp_srcs = {}
udp_one_flows = {}
udp_backscatters = {}
small_udp = {}
other_udp = {}

# dicts for ICMP traffic
icmp_flows = {}
icmp_srcs = {}
icmp_backscatters = {}
small_ping = {}
other_icmp = 0


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
            
            # Send to tcp_one_flow
            tcp_one_flow = tcp_traffic.tcp_one_flow(pkt, src_ip, dst_ip, dst_port, tcp_one_flows)
            if tcp_one_flow is not None:
                tcp_one_flows[(src_ip, dst_ip, dst_port)] = tcp_one_flow

            # Send to tcp_backscatter
            tcp_backscatter = tcp_traffic.tcp_backscatter_check(pkt, src_ip, tcp_backscatters)
            if tcp_backscatter is not None:
               tcp_backscatters[(src_ip)] = tcp_backscatter

            # Send to small_syn
            small_syn = tcp_traffic.small_syn_check(pkt, src_ip, small_syns)
            if small_syn is not None:
                small_syns[(src_ip)] = small_syn
        else:
            other_tcp += 1

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

print("---------------------")
print("TCP info:")
tcp_analysis.tcp_port_scan(tcp_flows)
tcp_analysis.tcp_network_scan(tcp_srcs)
tcp_analysis.one_flow(tcp_one_flows)
tcp_analysis.tcp_backscatter(tcp_backscatters)
tcp_analysis.small_syn(small_syns)
print("Other TCP: {}".format(int(other_tcp)))
print("---------------------")
print("UDP info:")
print("---------------------")
print("ICMP info:")
print("---------------------")