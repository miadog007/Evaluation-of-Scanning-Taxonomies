import dpkt
import socket
from tcp_analysis import tcp_traffic 

#udp_traffic, icmp_traffic

other = 0

pcap_file_path = 'data/CaptureOne.pcap'

for ts, pkt in dpkt.pcap.Reader(open(pcap_file_path, 'rb')):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
       
    if isinstance(ip, dpkt.ip.IP):
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            print('number 1')
            print(src_ip, dst_ip)
            tcp_traffic(src_ip, dst_ip)
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            continue
            #udp_traffic(ip)
        elif ip.p == dpkt.ip.IP_PROTO_ICMP:
            continue
            #icmp_traffic(ip)
        else:
            other += 1

print(f'Other: {other}')