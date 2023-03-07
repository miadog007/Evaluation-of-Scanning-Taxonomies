import dpkt
import socket
from flows import tcp_traffic, udp_traffic, icmp_traffic
from anlysis import tcp_analysis, udp_analysis, icmp_analysis
import time

packets = 0
minutes = 0
start_time = time.time()

total_packets = 0


# dict for tcp traffic
tcp_flows = {}
tcp_srcs = {}
tcp_one_flows = {}
tcp_backscatters = {}
small_syns = {}
other_tcp = {}

# dict for UDP traffic
udp_flows = {}
udp_srcs = {}
udp_one_flows = {}
udp_backscatters = {}
small_udps = {}
other_udp = {}

# dicts for ICMP traffic
icmp_srcs = {}
icmp_backscatters = {}
small_pings = {}
other_icmp = {}


# Main functions for finding TCP, UDP or ICMP packets
#for ts, pkt in dpkt.pcap.Reader(open('data/output_file_00000_20191203121948.pcap', 'rb')):
for ts, pkt in dpkt.pcap.Reader(open('data/CaptureOne.pcap', 'rb')):
    packets += 1
    total_packets += 1 
    # open packet with dpkt
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data

    # not working. still gets 1, 6 and 2 in other tcp
    if ip.p == 1 or 4 or 6 or 2:
        pass
        # Find TCP
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)

            if isinstance(ip.data, dpkt.tcp.TCP):
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

        # Find UDP
        if ip.p == dpkt.ip.IP_PROTO_UDP:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            dst_port = ip.data.dport

            # send to tcp_sinle_flow
            udp_flow = udp_traffic.udp_single_flow(pkt, src_ip, dst_ip, udp_flows)
            if udp_flow is not None:
                udp_flows[(src_ip, dst_ip)] = udp_flow

            udp_src = udp_traffic.udp_single_src(pkt, src_ip, dst_port, udp_srcs)
            if udp_src is not None:
                udp_srcs[(src_ip, dst_port)] = udp_src

            # Send to tcp_one_flow
            udp_one_flow = udp_traffic.udp_one_flow(pkt, src_ip, dst_ip, dst_port, udp_one_flows)
            if udp_one_flow is not None:
                udp_one_flows[(src_ip, dst_ip, dst_port)] = udp_one_flow
            
            # Send to udp_backscatter
            udp_backscatter = udp_traffic.udp_backscatter_check(pkt, src_ip, udp_backscatters)
            if udp_backscatter is not None:
                udp_backscatters[(src_ip)] = udp_backscatter

            # Send to small_udp
            small_udp = udp_traffic.small_udp_check(pkt, src_ip, small_udps)
            if small_udp is not None:
                small_udps[(src_ip)] = small_udp

    # Find ICMP
        if ip.p == dpkt.ip.IP_PROTO_ICMP:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)

            # Send to icmp_single_src
            icmp_src = icmp_traffic.icmp_single_src(pkt, src_ip, icmp_srcs)
            if icmp_src is not None:
                icmp_srcs[(src_ip)] = icmp_src

            # Send to icmp_backscatter
            icmp_backscatter = icmp_traffic.icmp_backscatter_check(pkt, src_ip, icmp_backscatters)
            if icmp_backscatter is not None:
                icmp_backscatters[(src_ip)] = icmp_backscatter

            # Send to small_ping
            small_ping = icmp_traffic.small_ping_check(pkt, src_ip, small_pings)
            if small_ping is not None:
                small_pings[(src_ip)] = small_ping


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


# Printing out result of each category in fukuda 2018
print("---------------------")
print('PCAP info:')
print(f'Number of packets: {total_packets}')
print("---------------------")
print("TCP info:")
tcp_analysis.tcp_port_scan(tcp_flows, other_tcp)
tcp_analysis.tcp_network_scan(tcp_srcs, other_tcp)
tcp_analysis.one_flow(tcp_one_flows, other_tcp)
tcp_analysis.tcp_backscatter(tcp_backscatters)
tcp_analysis.tcp_fragment(tcp_srcs, other_tcp)
tcp_analysis.small_syn(small_syns, other_tcp)
print(other_tcp)
tcp_other_packet = sum(other_tcp.values())
print(f"TCP other: {tcp_other_packet}")
print("---------------------")
print("UDP info:")
udp_analysis.udp_port_scan(udp_flows, other_udp)
udp_analysis.udp_network_scan(udp_srcs, other_udp)
udp_analysis.one_flow(udp_one_flows, other_udp)
udp_analysis.udp_backscatter(udp_backscatters)
udp_analysis.udp_fragment(udp_srcs, other_udp)
udp_analysis.small_udp(small_udps, other_udp)
udp_other_packet = sum(other_udp.values())
print(f"UDP other: {udp_other_packet}")
print("---------------------")
print("ICMP info:")
icmp_analysis.icmp_network_scan(icmp_srcs, other_icmp)
icmp_analysis.icmp_backscatter(icmp_backscatters)
icmp_analysis.icmp_fragment(icmp_srcs, other_icmp)
icmp_analysis.small_ping(small_pings, other_icmp)
icmp_other_packet = sum(other_icmp.values())
print(f"ICMP other: {icmp_other_packet}")
print("---------------------")
