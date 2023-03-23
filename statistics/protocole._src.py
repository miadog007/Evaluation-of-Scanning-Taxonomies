import dpkt
import socket

other = 0
tcp = 0
tcp_src = set()
udp = 0
udp_src = set()
icmp = 0
icmp_src = set()


for ts, pkt in dpkt.pcap.Reader(open('data/decmber_packets_00000_20201201074044.pcap', 'rb')):
#for ts, pkt in dpkt.pcap.Reader(open('data/CaptureOne.pcap', 'rb')):
    # open packet with dpkt
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data

    if eth.type==dpkt.ethernet.ETH_TYPE_IP:
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp += 1
            src_ip = socket.inet_ntoa(ip.src)
            if src_ip not in tcp_src:
                tcp_src.add(src_ip)
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            udp += 1
            src_ip = socket.inet_ntoa(ip.src)
            if src_ip not in udp_src:
                udp_src.add(src_ip)
        elif ip.p == dpkt.ip.IP_PROTO_ICMP:
            icmp += 1
            src_ip = socket.inet_ntoa(ip.src)
            if src_ip not in icmp_src:
                icmp_src.add(src_ip)
        else:
            other += 1


print(f'other: {other}')
print(f'TCP connections: {tcp}')
print(f'TCP Uniqe IP src: {len(tcp_src)}')
print(f'UDP connections: {udp}')
print(f'UDP Uniqe IP src: {len(udp_src)}')
print(f'ICMP connections {icmp}')
print(f'ICMP Uniqe IP src: {len(icmp_src)}')
        
