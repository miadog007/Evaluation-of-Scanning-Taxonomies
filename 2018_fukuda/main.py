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
tcp_hport_scans = {}
tcp_lport_scans = {}

tcp_srcs = {}
tcp_hnetwork_scans = {}
tcp_lnetwork_scans = {}

tcp_one_flows = {}
tcp_oflow_final = {}

tcp_backscatters = {}
tcp_bacsckatter_final = {}

tcp_fragment = {}

small_syns = {}
small_syns_final = {}

other_tcp = {}

# dict for UDP traffic
udp_flows = {}
udp_hport_scans = {}
udp_lport_scans = {}

udp_srcs = {}
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
icmp_srcs = {}
icmp_hnetwork_scans = {}
icmp_lnetwork_scans = {}

icmp_backscatters = {}
icmp_backscatter_final = {}

icmp_fragment = {}

small_pings = {}
small_pings_final = {}

other_icmp = {}

# set of ips
ip_src = set()

# others
other = 0

# Main functions for finding TCP, UDP or ICMP packets
#for ts, pkt in dpkt.pcap.Reader(open('data/decmber5_0__00000_20201230060725.pcap', 'rb')):
#for ts, pkt in dpkt.pcap.Reader(open('data/december5_00000_20201230060725.pcap', 'rb')):
for ts, pkt in dpkt.pcap.Reader(open('data/decmber_packets_00005_20201230060725.pcap', 'rb')):
#for ts, pkt in dpkt.pcap.Reader(open('data/decmber5_0__00003_20201230142725.pcap', 'rb')):
#for ts, pkt in dpkt.pcap.Reader(open('data/CaptureOne.pcap', 'rb')):
    packets += 1
    total_packets += 1 
    # open packet with dpkt
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data

    
    if eth.type==dpkt.ethernet.ETH_TYPE_IP: 
        if socket.inet_ntoa(ip.src) not in ip_src:
            ip_src.add(socket.inet_ntoa(ip.src))
        # Find TCP
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)

            if isinstance(ip.data, dpkt.tcp.TCP):
                dst_port = ip.data.dport
            #else:
             #   print('no dport tcp')
              #  other += 1        

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
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            if isinstance (ip.data, dpkt.udp.UDP) and ip.data.dport:
                dst_port = ip.data.dport  
            #else:
             #   print('no dport udp')
              #  other += 1  

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
        elif ip.p == dpkt.ip.IP_PROTO_ICMP:
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



# TCP analysis
tcp_analysis.tcp_port_scan(tcp_flows, other_tcp, tcp_hport_scans, tcp_lport_scans)
tcp_analysis.tcp_network_scan(tcp_srcs, other_tcp, tcp_hnetwork_scans, tcp_lnetwork_scans)
print('tcp check 1')
tcp_analysis.one_flow(tcp_one_flows, other_tcp, tcp_oflow_final)
tcp_analysis.tcp_backscatter(tcp_backscatters, tcp_bacsckatter_final)
tcp_analysis.tcp_fragment(tcp_srcs, other_tcp, tcp_fragment)
tcp_analysis.small_syn(small_syns, other_tcp, small_syns_final)

# UDP analysis
udp_analysis.udp_port_scan(udp_flows, other_udp, udp_hport_scans, udp_lport_scans)
udp_analysis.udp_network_scan(udp_srcs, other_udp, udp_hnetwork_scans, udp_lnetwork_scans)
print('udp check 1')
udp_analysis.one_flow(udp_one_flows, other_udp, udp_oflow_final)
udp_analysis.udp_backscatter(udp_backscatters, udp_backscatter_final)
udp_analysis.udp_fragment(udp_srcs, other_udp, udp_fragment)
udp_analysis.small_udp(small_udps, other_udp, small_udps_final)

# ICMP analysis
icmp_analysis.icmp_network_scan(icmp_srcs, other_icmp, icmp_hnetwork_scans, icmp_lnetwork_scans)
icmp_analysis.icmp_backscatter(icmp_backscatters, icmp_backscatter_final)
icmp_analysis.icmp_fragment(icmp_srcs, other_icmp, icmp_fragment)
icmp_analysis.small_ping(small_pings, other_icmp, small_pings_final)

# Fix other lists
tcp_analysis.tcp_remove_key_other(other_tcp, tcp_hport_scans, tcp_lport_scans, tcp_hnetwork_scans, tcp_lnetwork_scans, tcp_oflow_final, small_syns_final)
udp_analysis.udp_remove_key_other(other_udp, udp_hport_scans, udp_lport_scans, udp_hnetwork_scans, udp_lnetwork_scans, udp_oflow_final, small_udps_final)
icmp_analysis.icmp_remove_key_other(other_icmp, icmp_hnetwork_scans, icmp_lnetwork_scans, small_pings_final)

print('Anlysis part 1 done')

# Unique ip lists
# TCP
unique_tcp_hport_scans = set(key[0] for key in tcp_hport_scans.keys())
unique_tcp_lport_scans = set(key[0] for key in tcp_lport_scans.keys())
unique_tcp_hnetwork_scans = set(key[0] for key in tcp_hnetwork_scans.keys())
unique_tcp_lnetwork_scans = set(key[0] for key in tcp_lnetwork_scans.keys())
unique_tcp_one_flow = set(tcp_oflow_final.keys())
unique_tcp_back = set(tcp_bacsckatter_final.keys())
unique_tcp_fragment = set(tcp_fragment.keys())
unique_small_syns_final = set(small_syns_final.keys())
unique_other_tcp = set(other_tcp.keys())

# UDP
unique_udp_hport_scans = set(key[0] for key in udp_hport_scans.keys())
unique_udp_lport_scans = set(key[0] for key in udp_lport_scans.keys())
unique_udp_hnetwork_scans = set(key[0] for key in udp_hnetwork_scans.keys())
unique_udp_lnetwork_scans = set(key[0] for key in udp_lnetwork_scans.keys())
unique_udp_one_flow = set(udp_oflow_final.keys())
unique_udp_back = set(udp_backscatter_final.keys())
unique_udp_fragment = set(udp_fragment.keys())
unique_small_udps_final = set(small_udps_final.keys())
unique_other_udp = set(other_udp.keys())


# ICMP
unique_icmp_hnetwork_scans = set(key[0] for key in icmp_hnetwork_scans.keys())
unique_icmp_lnetwork_scans = set(key[0] for key in icmp_lnetwork_scans.keys())
unique_icmp_back = set(icmp_backscatter_final.keys())
unique_icmp_fragment = set(icmp_fragment.keys())
unique_small_pings_final = set(small_pings_final.keys())
unique_other_icmp = set(other_icmp.keys())

labled_sources = (len(tcp_hport_scans.keys()) + len(tcp_lport_scans.keys()) +
                  len(tcp_hnetwork_scans.keys()) + len(tcp_lnetwork_scans.keys()) +
                  len(tcp_oflow_final.keys()) + len(tcp_bacsckatter_final.keys()) + 
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

unique_labled_sources_tcp = (len(unique_tcp_hport_scans) + len(unique_tcp_lport_scans) + 
                            len(unique_tcp_hnetwork_scans) + len(unique_tcp_lnetwork_scans) +
                            len(unique_tcp_one_flow) + len(unique_tcp_back) + 
                            len(unique_tcp_fragment) + len(unique_small_syns_final) + 
                            len(unique_other_tcp))

unique_labled_sources_udp = (len(unique_udp_hport_scans) + len(unique_udp_lport_scans) + 
                            len(unique_udp_hnetwork_scans) + len(unique_udp_lnetwork_scans) +
                            len(unique_udp_one_flow) + len(unique_udp_back) + 
                            len(unique_udp_fragment) + len(unique_small_udps_final) + 
                            len(unique_other_udp))

unique_labled_sources_icmp = (len(unique_icmp_hnetwork_scans) + len(unique_icmp_lnetwork_scans) +
                            len(unique_icmp_back) + len(unique_icmp_fragment) +
                            len(unique_small_pings_final) + len(unique_other_icmp))

unique_labled_sources = unique_labled_sources_tcp + unique_labled_sources_udp + unique_labled_sources_icmp 

print(unique_labled_sources)
print(unique_labled_sources_tcp)
print(unique_labled_sources_udp)
print(unique_labled_sources_icmp)

# Printing out result of each category in fukuda 2018
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
print(f'TCP Backscatter: {len(tcp_bacsckatter_final.keys())}')
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

""" for key, value in other_tcp.items():
    if key == '102.165.30.33':
        print(key, value) """

#for key, value in tcp_lport_scans.items():
  #  if key[0] == '89.248.165.33':
   #     print(f"Key: {key}, Value: {value}")

""" unique = set(key[0] for key in udp_lnetwork_scans.keys())
unique2 = set(key[0] for key in udp_lport_scans.keys())
unique3 = set(key for key in small_udps_final.keys())

print('port light')
print(len(unique2))
print('network light')
print(len(unique))
print('small')
print(len(unique3)) """

from collections import Counter

""" dst_port_counter_one_tcp = Counter()
print('tcp one flows')
# Loop over the dictionary and update the counter with each dst port
for key, value in tcp_oflow_final.items():
    dst_port = value['dst_port']
    dst_port_counter_one_tcp[dst_port] += 1

# Loop over the counter and print the dst ports with their corresponding counts
for dst_port, count_tcp_one in dst_port_counter_one_tcp.items():
    if count_tcp_one > 100: 
        print(f"dst_port {dst_port} is represented {count_tcp_one} times")

dst_port_counter_one_udp = Counter()
print('UDP one flows')
# Loop over the dictionary and update the counter with each dst port
for key, value in udp_oflow_final.items():
    dst_port = value['dst_port']
    dst_port_counter_one_udp[dst_port] += 1

# Loop over the counter and print the dst ports with their corresponding counts
for dst_port, count_udp_one in dst_port_counter_one_udp.items():
    if count_udp_one > 100: 
        print(f"dst_port {dst_port} is represented {count_udp_one} times") """
    
""" dst_port_counter_back_tcp = Counter()
print('TCP back')
# Loop over the dictionary and update the counter with each dst port
for key, value in small_syns_final.items():
    dst_ports = value['dst_ports']
    for dst_port in dst_ports:
        if isinstance(dst_port, int):
            dst_port_counter_back_tcp[dst_port] += 1
        else:
            for port in dst_port:
                dst_port_counter_back_tcp[port] += 1

# Loop over the counter and print the dst ports with their corresponding counts
for dst_port, count_tcp_bck in dst_port_counter_back_tcp.items():
    if count_tcp_bck > 100: 
        print(f"dst_port {dst_port} is represented {count_tcp_bck} times")

dst_port_counter_back_udp = Counter()
print('UDP back')
# Loop over the dictionary and update the counter with each dst port
for key, value in small_udps_final.items():
    dst_ports = value['dst_ports']
    for dst_port in dst_ports:
        if isinstance(dst_port, int):
            dst_port_counter_back_udp[dst_port] += 1
        else:
            for port in dst_port:
                dst_port_counter_back_udp[port] += 1

# Loop over the counter and print the dst ports with their corresponding counts
for dst_port, count_udp_bck in dst_port_counter_back_udp.items():
    if count_udp_bck > 100: 
        print(f"dst_port {dst_port} is represented {count_udp_bck} times") """
 




""" # Find multiple categorized traffic.
common_keys = set(key[0] for key in udp_lnetwork_scans.keys()) & set(key[0] for key in udp_lport_scans.keys())

extra_keys = set(key[0] for key in udp_lport_scans.keys()) & set(key[0] for key in udp_hport_scans.keys()) - common_keys

# find only in port scans
#for key in tcp_lport_scans.keys():
 #   if key[0] in extra_keys:
  #      value = tcp_lport_scans[key]
   #     print(key, value['num_packets'])



for key in common_keys:
    count_lnetwork = 0
    for key in tcp_lnetwork_scans.keys():
        if key[0] in common_keys:
            count_lnetwork += 1
    count_lport = 0
    for key in tcp_lport_scans.keys():
        if key[0] in common_keys:
            count_lport += 1

print(f'network: {count_lnetwork}')
print(f'port: {count_lport}') """

""" keys = [*tcp_hport_scans.keys(), *tcp_lport_scans.keys()]
tcp_port = set(tuple(key[0] for key in keys))
#tcp_port2 = [ip[0] for ip in tcp_port]
tcp_port_f = ', '.join(tcp_port)

keys = [*tcp_hnetwork_scans.keys(), *tcp_lnetwork_scans.keys()]
tcp_network = set(tuple(key[0] for key in keys))
#tcp_network2 = [ip[0] for ip in tcp_network]
tcp_network_f = ', '.join(tcp_network)

keys = [*tcp_oflow_final]
tcp_oflow = set(tuple(key[0] for key in keys))
#tcp_network2 = [ip[0] for ip in tcp_network]
tcp_oflow_f = ', '.join(tcp_oflow)

keys = [*tcp_bacsckatter_final]
tcp_back = set(tuple(key for key in keys))
#tcp_network2 = [ip[0] for ip in tcp_network]
tcp_back_f = ', '.join(tcp_back)

keys = [*small_syns_final]
tcp_small = set(tuple(key for key in keys))
#tcp_network2 = [ip[0] for ip in tcp_network]
tcp_small_f = ', '.join(tcp_small)

keys = [*other_tcp]
tcp_other1 = set(tuple(key for key in keys))
#tcp_network2 = [ip[0] for ip in tcp_network]
tcp_other_f = ', '.join(tcp_other1)

with open('tcp_port_fukuda.txt', 'w') as f:
    f.write(tcp_port_f)

with open('tcp_network_fukuda.txt', 'w') as f:
    f.write(tcp_network_f)

with open('tcp_oflow_fukuda.txt', 'w') as f:
    f.write(tcp_oflow_f)

with open('tcp_back_fukuda.txt', 'w') as f:
    f.write(tcp_back_f)

with open('tcp_small_fukuda.txt', 'w') as f:
    f.write(tcp_small_f)

with open('tcp_other_fukuda.txt', 'w') as f:
    f.write(tcp_other_f)

keys = [*udp_hport_scans.keys(), *udp_lport_scans.keys()]
udp_port = set(tuple(key[0] for key in keys))
#udp_port2 = [ip[0] for ip in udp_port]
udp_port_f = ', '.join(udp_port)

keys = [*udp_hnetwork_scans.keys(), *udp_lnetwork_scans.keys()]
udp_network = set(tuple(key[0] for key in keys))
#udp_network2 = [ip[0] for ip in udp_network]
udp_network_f = ', '.join(udp_network)

keys = [*udp_oflow_final]
udp_oflow = set(tuple(key[0] for key in keys))
#udp_network2 = [ip[0] for ip in udp_network]
udp_oflow_f = ', '.join(udp_oflow)

keys = [*udp_backscatter_final]
udp_back = set(tuple(key for key in keys))
#udp_network2 = [ip[0] for ip in udp_network]
udp_back_f = ', '.join(udp_back)

keys = [*small_udps_final]
udp_small = set(tuple(key for key in keys))
#udp_network2 = [ip[0] for ip in udp_network]
udp_small_f = ', '.join(udp_small)

keys = [*other_udp]
udp_other1 = set(tuple(key for key in keys))
#udp_network2 = [ip[0] for ip in udp_network]
udp_other_f = ', '.join(udp_other1)

with open('udp_port_fukuda.txt', 'w') as f:
    f.write(udp_port_f)

with open('udp_network_fukuda.txt', 'w') as f:
    f.write(udp_network_f)

with open('udp_oflow_fukuda.txt', 'w') as f:
    f.write(udp_oflow_f)

with open('udp_back_fukuda.txt', 'w') as f:
    f.write(udp_back_f)

with open('udp_small_fukuda.txt', 'w') as f:
    f.write(udp_small_f)

with open('udp_other_fukuda.txt', 'w') as f:
    f.write(udp_other_f)

keys = [*icmp_hnetwork_scans.keys(), *icmp_lnetwork_scans.keys()]
icmp_network = set(tuple(key for key in keys))
#icmp_network2 = [ip[0] for ip in icmp_network]
icmp_network_f = ', '.join(icmp_network)

keys = [*icmp_backscatter_final]
icmp_back = set(tuple(key for key in keys))
#icmp_network2 = [ip[0] for ip in icmp_network]
icmp_back_f = ', '.join(icmp_back)

keys = [*small_pings_final]
icmp_small = set(tuple(key for key in keys))
#icmp_network2 = [ip[0] for ip in icmp_network]
icmp_small_f = ', '.join(icmp_small)

keys = [*other_icmp]
icmp_other1 = set(tuple(key for key in keys))
#icmp_network2 = [ip[0] for ip in icmp_network]
icmp_other_f = ', '.join(icmp_other1)

with open('icmp_network_fukuda.txt', 'w') as f:
    f.write(icmp_network_f)

with open('icmp_back_fukuda.txt', 'w') as f:
    f.write(icmp_back_f)

with open('icmp_small_fukuda.txt', 'w') as f:
    f.write(icmp_small_f)

with open('icmp_other_fukuda.txt', 'w') as f:
    f.write(icmp_other_f) """

with open('december_fukuda_unique_src.txt', 'a') as f:
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
    #f.write(f'Other Traffic {other}\n')
    #f.write("---------------------\n") 

""" with open('tcp_heavy_port_scans_fukuda.txt', 'a') as f:
    f.write(str(tcp_hport_scans))
with open('tcp_light_port_scans_fukuda.txt', 'a') as f:   
    f.write(str(tcp_lport_scans))
with open('tcp_heavy_network_scans_fukuda.txt', 'a') as f:
    f.write(str(tcp_hnetwork_scans))
with open('tcp_light_network_scans_fukuda.txt', 'a') as f:   
    f.write(str(tcp_lnetwork_scans))
with open('tcp_one_flows_fukuda.txt', 'a') as f:
    f.write(str(tcp_oflow_final))
with open('tcp_backscatter_fukuda.txt', 'a') as f:
    f.write(str(tcp_bacsckatter_final))
with open('tcp_small_fukuda.txt', 'a') as f:
    f.write(str(small_syns_final))
with open('tcp_other_fukuda.txt', 'a') as f:
    f.write(str(other_tcp))

with open('udp_heavy_port_scans_fukuda.txt', 'a') as f:
    f.write(str(udp_hport_scans))
with open('udp_light_port_scans_fukuda.txt', 'a') as f:   
    f.write(str(udp_lport_scans))
with open('udp_heavy_network_scans_fukuda.txt', 'a') as f:
    f.write(str(udp_hnetwork_scans))
with open('udp_light_network_scans_fukuda.txt', 'a') as f:   
    f.write(str(udp_lnetwork_scans))
with open('udp_one_flows_fukuda.txt', 'a') as f:
    f.write(str(udp_oflow_final))
with open('fragment_fukuda.txt', 'a') as f:
    f.write(str(udp_fragment))
with open('udp_backscatter_fukuda.txt', 'a') as f:
    f.write(str(udp_backscatter_final))
with open('udp_small_fukuda.txt', 'a') as f:
    f.write(str(small_udps_final))
with open('udp_other_fukuda.txt', 'a') as f:
    f.write(str(other_udp))

with open('icmp_heavy_network_scans_fukuda.txt', 'a') as f:
    f.write(str(icmp_hnetwork_scans))
with open('icmp_light_network_scans_fukuda.txt', 'a') as f:   
    f.write(str(icmp_lnetwork_scans))
with open('icmp_backscatter_fukuda.txt', 'a') as f:
    f.write(str(icmp_backscatter_final))
with open('icmp_small_fukuda.txt', 'a') as f:
    f.write(str(small_pings_final))
with open('icmp_other_fukuda.txt', 'a') as f:
    f.write(str(other_icmp))
 """