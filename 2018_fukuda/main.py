import dpkt
import socket
from flows import tcp_traffic, udp_traffic, icmp_traffic
from anlysis import tcp_analysis, udp_analysis, icmp_analysis
import time



# Counter fro number of packets and number of minutes
# Packets reset every minute
packets = 0
minutes = 0
start_time = time.time()

# Counter for number of packets in Packet Capture
total_packets = 0

'''
Initialazing all dicts for printing out 
infomration of anomaly-traffic from main.py
'''
# dicts for tcp traffic
tcp_port_flows = {}
tcp_hport_scans = {}
tcp_lport_scans = {}

tcp_network_flows = {}
tcp_hnetwork_scans = {}
tcp_lnetwork_scans = {}

tcp_one_flows = {}
tcp_oflow_final = {}

tcp_backscatters = {}
tcp_backscatter_final = {}

tcp_fragment = {}

small_syns = {}
small_syns_final = {}

other_tcp = {}

# dicts for UDP traffic
udp_port_flows = {}
udp_hport_scans = {}
udp_lport_scans = {}

udp_network_flows = {}
udp_hnetwork_scans = {}
udp_lnetwork_scans = {}

udp_one_flows = {}
udp_oflow_final = {}

udp_backscatters = {}
udp_backscatter_final = {}

udp_fragment = {}

small_udps = {}
small_udps_final = {}

other_udp = {}

# dicts for ICMP traffic
icmp_network_flows = {}
icmp_hnetwork_scans = {}
icmp_lnetwork_scans = {}

icmp_backscatters = {}
icmp_backscatter_final = {}

icmp_fragment = {}

small_pings = {}
small_pings_final = {}

other_icmp = {}

# set of unique IPs
ip_src = set()

# Counter for Other traffic
other = 0

# Insert Packet Capture
pcap = 'data/mar_packets_00000_20210301072506.pcap'
#pcap = 'data/CaptureOne.pcap'

# Main functions for finding TCP, UDP or ICMP packets
for ts, pkt in dpkt.pcap.Reader(open(pcap, 'rb')):
    '''
    Open Packet Capture file with dpkt.
    Finds TCP, UDP and ICMP traffic.
    Sends all Packets to flow functions in "flows" folder
    '''
    packets += 1
    total_packets += 1
    # open packet with dpkt
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data

    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        if socket.inet_ntoa(ip.src) not in ip_src:
            ip_src.add(socket.inet_ntoa(ip.src))
        
        # Find TCP
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)

            if isinstance(ip.data, dpkt.tcp.TCP):
                dst_port = ip.data.dport

                # send to tcp_sinle_flow
                tcp_flow = tcp_traffic.tcp_single_flow(
                    pkt, src_ip, dst_ip, tcp_port_flows)
                if tcp_flow is not None:
                    tcp_port_flows[(src_ip, dst_ip)] = tcp_flow

                # Send to tcp_single_src
                tcp_src = tcp_traffic.tcp_single_src(
                    pkt, src_ip, dst_port, tcp_network_flows)
                if tcp_src is not None:
                    tcp_network_flows[(src_ip, dst_port)] = tcp_src

                # Send to tcp_one_flow
                tcp_one_flow = tcp_traffic.tcp_one_flow(
                    pkt, src_ip, dst_ip, dst_port, tcp_one_flows)
                if tcp_one_flow is not None:
                    tcp_one_flows[(src_ip, dst_ip, dst_port)] = tcp_one_flow

                # Send to tcp_backscatter
                tcp_backscatter = tcp_traffic.tcp_backscatter_check(
                    pkt, src_ip, tcp_backscatters)
                if tcp_backscatter is not None:
                    tcp_backscatters[(src_ip)] = tcp_backscatter

                # Send to small_syn
                small_syn = tcp_traffic.small_syn_check(
                    pkt, src_ip, small_syns)
                if small_syn is not None:
                    small_syns[(src_ip)] = small_syn

        # Find UDP
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            if isinstance(ip.data, dpkt.udp.UDP) and ip.data.dport:
                dst_port = ip.data.dport

            # send to tcp_sinle_flow
            udp_flow = udp_traffic.udp_single_flow(
                pkt, src_ip, dst_ip, udp_port_flows)
            if udp_flow is not None:
                udp_port_flows[(src_ip, dst_ip)] = udp_flow

            udp_src = udp_traffic.udp_single_src(
                pkt, src_ip, dst_port, udp_network_flows)
            if udp_src is not None:
                udp_network_flows[(src_ip, dst_port)] = udp_src

            # Send to tcp_one_flow
            udp_one_flow = udp_traffic.udp_one_flow(
                pkt, src_ip, dst_ip, dst_port, udp_one_flows)
            if udp_one_flow is not None:
                udp_one_flows[(src_ip, dst_ip, dst_port)] = udp_one_flow

            # Send to udp_backscatter
            udp_backscatter = udp_traffic.udp_backscatter_check(
                pkt, src_ip, udp_backscatters)
            if udp_backscatter is not None:
                udp_backscatters[(src_ip)] = udp_backscatter

            # Send to small_udp
            small_udp = udp_traffic.small_udp_check(pkt, src_ip, small_udps)
            if small_udp is not None:
                small_udps[(src_ip)] = small_udp

    # Find ICMP
        elif ip.p == dpkt.ip.IP_PROTO_ICMP:
            if hasattr(ip, 'icmp'):
                if hasattr(ip.icmp, 'type'):
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)

                    # Send to icmp_single_src
                    icmp_src = icmp_traffic.icmp_single_src(pkt, src_ip, icmp_network_flows)
                    if icmp_src is not None:
                        icmp_network_flows[(src_ip)] = icmp_src

                    # Send to icmp_backscatter
                    icmp_backscatter = icmp_traffic.icmp_backscatter_check(
                        pkt, icmp_backscatters)
                    if icmp_backscatter is not None:
                        icmp_backscatters[(src_ip)] = icmp_backscatter

                    # Send to small_ping
                    small_ping = icmp_traffic.small_ping_check(pkt, small_pings)
                    if small_ping is not None:
                        small_pings[(src_ip)] = small_ping
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
            print(
                f"Number of packets processed in the {minutes}st minute:", packets)
        elif minutes == 2:
            print(
                f"Number of packets processed in the {minutes}nd minute:", packets)
        elif minutes == 3:
            print(
                f"Number of packets processed in the {minutes}rd minute:", packets)
        else:
            print(
                f"Number of packets processed in the {minutes}th minute:", packets)
        packets = 0
        start_time = time.time()


# TCP analysis
tcp_analysis.tcp_port_scan(
    tcp_port_flows, other_tcp, tcp_hport_scans, tcp_lport_scans)
tcp_analysis.tcp_network_scan(
    tcp_network_flows, other_tcp, tcp_hnetwork_scans, tcp_lnetwork_scans)
print('TCP analysis check 1')
tcp_analysis.one_flow(tcp_one_flows, other_tcp, tcp_oflow_final)
tcp_analysis.tcp_backscatter(tcp_backscatters, tcp_backscatter_final)
tcp_analysis.tcp_fragment(tcp_network_flows, other_tcp, tcp_fragment)
tcp_analysis.small_syn(small_syns, other_tcp, small_syns_final)

# UDP analysis
udp_analysis.udp_port_scan(
    udp_port_flows, other_udp, udp_hport_scans, udp_lport_scans)
udp_analysis.udp_network_scan(
    udp_network_flows, other_udp, udp_hnetwork_scans, udp_lnetwork_scans)
print('UDP analysis check 1')
udp_analysis.one_flow(udp_one_flows, other_udp, udp_oflow_final)
udp_analysis.udp_backscatter(udp_backscatters, udp_backscatter_final)
udp_analysis.udp_fragment(udp_network_flows, other_udp, udp_fragment)
udp_analysis.small_udp(small_udps, other_udp, small_udps_final)

# ICMP analysis
icmp_analysis.icmp_network_scan(
    icmp_network_flows, other_icmp, icmp_hnetwork_scans, icmp_lnetwork_scans)
icmp_analysis.icmp_backscatter(icmp_backscatters, icmp_backscatter_final)
icmp_analysis.icmp_fragment(icmp_network_flows, other_icmp, icmp_fragment)
icmp_analysis.small_ping(small_pings, other_icmp, small_pings_final)

# Sends dicts for clean up in Other dicts
tcp_analysis.tcp_remove_key_other(other_tcp, tcp_hport_scans, tcp_lport_scans,
                                  tcp_hnetwork_scans, tcp_lnetwork_scans, tcp_oflow_final, small_syns_final)
udp_analysis.udp_remove_key_other(other_udp, udp_hport_scans, udp_lport_scans,
                                  udp_hnetwork_scans, udp_lnetwork_scans, udp_oflow_final, small_udps_final)
icmp_analysis.icmp_remove_key_other(other_icmp, icmp_hnetwork_scans, icmp_lnetwork_scans, small_pings_final)
print('Anlysis part 1 done')

# Get all unique IP sources for each anomaly in TCÅ
unique_tcp_hport_scans = set(key[0] for key in tcp_hport_scans.keys())
unique_tcp_lport_scans = set(key[0] for key in tcp_lport_scans.keys())
unique_tcp_hnetwork_scans = set(key[0] for key in tcp_hnetwork_scans.keys())
unique_tcp_lnetwork_scans = set(key[0] for key in tcp_lnetwork_scans.keys())
unique_tcp_one_flow = set(tcp_oflow_final.keys())
unique_tcp_back = set(tcp_backscatter_final.keys())
unique_tcp_fragment = set(tcp_fragment.keys())
unique_small_syns_final = set(small_syns_final.keys())
unique_other_tcp = set(other_tcp.keys())

# Get all unique IP sources for each anomaly in UDP
unique_udp_hport_scans = set(key[0] for key in udp_hport_scans.keys())
unique_udp_lport_scans = set(key[0] for key in udp_lport_scans.keys())
unique_udp_hnetwork_scans = set(key[0] for key in udp_hnetwork_scans.keys())
unique_udp_lnetwork_scans = set(key[0] for key in udp_lnetwork_scans.keys())
unique_udp_one_flow = set(udp_oflow_final.keys())
unique_udp_back = set(udp_backscatter_final.keys())
unique_udp_fragment = set(udp_fragment.keys())
unique_small_udps_final = set(small_udps_final.keys())
unique_other_udp = set(other_udp.keys())

# Get all unique IP sources for each anomaly in ICMP
unique_icmp_hnetwork_scans = set(key[0] for key in icmp_hnetwork_scans.keys())
unique_icmp_lnetwork_scans = set(key[0] for key in icmp_lnetwork_scans.keys())
unique_icmp_back = set(icmp_backscatter_final.keys())
unique_icmp_fragment = set(icmp_fragment.keys())
unique_small_pings_final = set(small_pings_final.keys())
unique_other_icmp = set(other_icmp.keys())

# Sum all labled IP sources
labled_sources = (len(tcp_hport_scans.keys()) + len(tcp_lport_scans.keys()) +
                  len(tcp_hnetwork_scans.keys()) + len(tcp_lnetwork_scans.keys()) +
                  len(tcp_oflow_final.keys()) + len(tcp_backscatter_final.keys()) +
                  len(tcp_fragment.keys()) + len(small_syns_final.keys()) +
                  len(other_tcp.keys()) +
                  len(udp_hport_scans.keys()) + len(udp_lport_scans.keys()) +
                  len(udp_hnetwork_scans.keys()) + len(udp_lnetwork_scans.keys()) +
                  len(udp_oflow_final.keys()) + len(udp_backscatter_final.keys()) +
                  len(udp_fragment.keys()) + len(small_udps_final.keys()) +
                  len(other_udp.keys()) +
                  len(icmp_hnetwork_scans.keys()) + len(icmp_lnetwork_scans.keys()) +
                  len(icmp_backscatter_final.keys()) + len(icmp_fragment.keys()) +
                  len(small_pings_final.keys()) + len(other_icmp.keys()))

# Sum all unique labled IP sources for TCP
unique_labled_sources_tcp = (len(unique_tcp_hport_scans) + len(unique_tcp_lport_scans) +
                             len(unique_tcp_hnetwork_scans) + len(unique_tcp_lnetwork_scans) +
                             len(unique_tcp_one_flow) + len(unique_tcp_back) +
                             len(unique_tcp_fragment) + len(unique_small_syns_final) +
                             len(unique_other_tcp))

# Sum all unique labled IP sources for UDP
unique_labled_sources_udp = (len(unique_udp_hport_scans) + len(unique_udp_lport_scans) +
                             len(unique_udp_hnetwork_scans) + len(unique_udp_lnetwork_scans) +
                             len(unique_udp_one_flow) + len(unique_udp_back) +
                             len(unique_udp_fragment) + len(unique_small_udps_final) +
                             len(unique_other_udp))

# Sum all unique labled IP sources for ICMP
unique_labled_sources_icmp = (len(unique_icmp_hnetwork_scans) + len(unique_icmp_lnetwork_scans) +
                              len(unique_icmp_back) + len(unique_icmp_fragment) +
                              len(unique_small_pings_final) + len(unique_other_icmp))

# Sum all unique labled IP sources
unique_labled_sources = unique_labled_sources_tcp + \
    unique_labled_sources_udp + unique_labled_sources_icmp


# Printing out result of each category in Liu & Fukuda 2018
print("---------------------")
print('PCAP info:')
print(f'Number of packets: {total_packets}')
print(f'Number of src ips: {(len(ip_src))}')
print(f'Labled traffic: {labled_sources}')
print("---------------------")
print('TCP info:')
print(f'TCP Heavy Port scans: {len(unique_tcp_hport_scans)}')
print(f'TCP Light pors scans: {len(tcp_lport_scans.keys())}')
print(f'TCP Heavy Network scans: {len(unique_tcp_hnetwork_scans)}')
print(f'TCP Light Network scans: {len(tcp_lnetwork_scans.keys())}')
print(f'TCP One Flows: {len(tcp_oflow_final.keys())}')
print(f'TCP Backscatter: {len(tcp_backscatter_final.keys())}')
print(f"TCP IP Fragement: {len(tcp_fragment.keys())}")
print(f'TCP Small SYN: {len(small_syns_final.keys())}')
print(f'Other TCP: {len(other_tcp.keys())}')
print(f'Other TCP unique: {len(unique_other_tcp)}')
print("---------------------")
print('UDP Info:')
print(f'UDP Heavy Port scans: {len(udp_hport_scans.keys())}')
print(f'UDP Light Port scans: {len(udp_lport_scans.keys())}')
print(f'UDP Heavy Network scans: {len(udp_hnetwork_scans.keys())}')
print(f'UDP Light Network scans: {len(udp_lnetwork_scans.keys())}')
print(f'UDP One Flows: {len(udp_oflow_final.keys())}')
print(f'UDP Backscatter: {len(udp_backscatter_final.keys())}')
print(f"UDP IP Fragement: {len(udp_fragment.keys())}")
print(f'UDP Small UDP: {len(small_udps_final.keys())}')
print(f'Other UDP: {(len(other_udp.keys()))}')
print("---------------------")
print('ICMP Info:')
print(f'ICMP Heavy Network scans: {len(icmp_hnetwork_scans.keys())}')
print(f'ICMP Light Network scans: {len(icmp_lnetwork_scans.keys())}')
print(f'ICMP Backscatter: {len(icmp_backscatter_final.keys())}')
print(f"ICMP IP Fragement: {len(icmp_fragment.keys())}")
print(f'Small Pings:  {len(small_pings_final.keys())}')
print(f'Other ICMP: {(len(other_icmp.keys()))}')
print("---------------------")
print(f'Other Traffic {other}')
print("---------------------")

with open('full-list-mar/mar_1-7_fukuda_unique_src.txt', 'a') as f:
    f.write("---------------------\n")
    f.write('PCAP info:\n')
    f.write(f'Number of packets: {total_packets}\n')
    f.write(f'Number of src ips: {(len(ip_src))}\n')
    f.write(f'Labled src ips: {labled_sources}\n')
    f.write(f'Unique labled src ips: {unique_labled_sources}\n')
    f.write("---------------------\n")
    f.write('TCP info:\n')
    f.write(f'Unique labled TCP src ips: {unique_labled_sources_tcp}\n')
    f.write(f'TCP Heavy Port scans: {len(unique_tcp_hport_scans)}\n')
    f.write(f'TCP Light Port scans: {len(unique_tcp_lport_scans)}\n')
    f.write(f'TCP Heavy Network scans: {len(unique_tcp_hnetwork_scans)}\n')
    f.write(f'TCP Light Network scans: {len(unique_tcp_lnetwork_scans)}\n')
    f.write(f'TCP One Flows: {len(unique_tcp_one_flow)}\n')
    f.write(f'TCP Backscatter: {len(unique_tcp_back)}\n')
    f.write(f"TCP IP Fragement: {len(unique_tcp_fragment)}\n")
    f.write(f'TCP Small SYN: {len(unique_small_syns_final)}\n')
    f.write(f'Other TCP: {(len(unique_other_tcp))}\n')
    f.write("---------------------\n")
    f.write('UDP Info:\n')
    f.write(f'Unique labled UDP src ips: {unique_labled_sources_udp}\n')
    f.write(f'UDP Heavy Port scans: {len(unique_udp_hport_scans)}\n')
    f.write(f'UDP Light Port scans: {len(unique_udp_lport_scans)}\n')
    f.write(f'UDP Heavy Network scans: {len(unique_udp_hnetwork_scans)}\n')
    f.write(f'UDP Light Network scans: {len(unique_udp_lnetwork_scans)}\n')
    f.write(f'UDP One Flows: {len(unique_udp_one_flow)}\n')
    f.write(f'UDP Backscatter: {len(unique_udp_back)}\n')
    f.write(f"UDP IP Fragement: {len(unique_udp_fragment)}\n")
    f.write(f'UDP Small UDP: {len(unique_small_udps_final)}\n')
    f.write(f'Other UDP: {(len(unique_other_udp))}\n')
    f.write("---------------------\n")
    f.write('ICMP Info:\n')
    f.write(f'Unique labled ICMP src ips: {unique_labled_sources_icmp}\n')
    f.write(f'ICMP Heavy Network scans: {len(unique_icmp_hnetwork_scans)}\n')
    f.write(f'ICMP Light Network scans: {len(unique_icmp_lnetwork_scans)}\n')
    f.write(f'ICMP Backscatter: {len(unique_icmp_back)}\n')
    f.write(f"ICMP IP Fragement: {len(unique_icmp_fragment)}\n")
    f.write(f'Small Pings:  {len(unique_small_pings_final)}\n')
    f.write(f'Other ICMP: {(len(unique_other_icmp))}\n') 
    f.write("---------------------\n")

with open('full-list-mar/tcp_heavy_port_scans_fukuda.txt', 'a') as f:
    f.write(str(tcp_hport_scans))
with open('full-list-mar/tcp_light_port_scans_fukuda.txt', 'a') as f:   
    f.write(str(tcp_lport_scans))
with open('full-list-mar/tcp_heavy_network_scans_fukuda.txt', 'a') as f:
    f.write(str(tcp_hnetwork_scans))
with open('full-list-mar/tcp_light_network_scans_fukuda.txt', 'a') as f:   
    f.write(str(tcp_lnetwork_scans))
with open('full-list-mar/tcp_one_flows_fukuda.txt', 'a') as f:
    f.write(str(tcp_oflow_final))
with open('full-list-mar/tcp_backscatter_fukuda.txt', 'a') as f:
    f.write(str(tcp_backscatter_final))
with open('full-list-mar/tcp_small_fukuda.txt', 'a') as f:
    f.write(str(small_syns_final))
with open('full-list-mar/tcp_other_fukuda.txt', 'a') as f:
    f.write(str(other_tcp))

with open('full-list-mar/udp_heavy_port_scans_fukuda.txt', 'a') as f:
    f.write(str(udp_hport_scans))
with open('full-list-mar/udp_light_port_scans_fukuda.txt', 'a') as f:   
    f.write(str(udp_lport_scans))
with open('full-list-mar/udp_heavy_network_scans_fukuda.txt', 'a') as f:
    f.write(str(udp_hnetwork_scans))
with open('full-list-mar/udp_light_network_scans_fukuda.txt', 'a') as f:   
    f.write(str(udp_lnetwork_scans))
with open('full-list-mar/udp_one_flows_fukuda.txt', 'a') as f:
    f.write(str(udp_oflow_final))
with open('full-list-mar/fragment_fukuda.txt', 'a') as f:
    f.write(str(udp_fragment))
with open('full-list-mar/udp_backscatter_fukuda.txt', 'a') as f:
    f.write(str(udp_backscatter_final))
with open('full-list-mar/udp_small_fukuda.txt', 'a') as f:
    f.write(str(small_udps_final))
with open('full-list-mar/udp_other_fukuda.txt', 'a') as f:
    f.write(str(other_udp))

with open('full-list-mar/icmp_heavy_network_scans_fukuda.txt', 'a') as f:
    f.write(str(icmp_hnetwork_scans))
with open('full-list-mar/icmp_light_network_scans_fukuda.txt', 'a') as f:   
    f.write(str(icmp_lnetwork_scans))
with open('full-list-mar/icmp_backscatter_fukuda.txt', 'a') as f:
    f.write(str(icmp_backscatter_final))
with open('full-list-mar/icmp_small_fukuda.txt', 'a') as f:
    f.write(str(small_pings_final))
with open('full-list-mar/icmp_other_fukuda.txt', 'a') as f:
    f.write(str(other_icmp))