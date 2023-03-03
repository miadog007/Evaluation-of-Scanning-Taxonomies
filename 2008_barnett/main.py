import dpkt
import socket
import time

packets = 0
minutes = 0
start_time = time.time()


#for ts, pkt in dpkt.pcap.Reader(open('data/anon_196-21-146/test/output_file_00000_20191203121948.pcap', 'rb')):
for ts, buf in dpkt.pcap.Reader(open('data/CaptureOne.pcap', 'rb')):
    packets += 1
    
    eth = dpkt.ethernet.Ethernet(buf)

    # Check if the packet is a Layer 2 scan (ARP or LLDP)
    if eth.type == dpkt.ethernet.ETH_TYPE_ARP or eth.type == dpkt.ethernet.ETH_TYPE_LLDP:
        print("Layer 2 scan:", eth.type)

    # Check if the packet is a Layer 3 scan (ICMP, TCP, or UDP)
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip = eth.data
        if ip.p == dpkt.ip.IP_PROTO_ICMP:
            print("Layer 3 scan: ICMP")
        elif ip.p == dpkt.ip.IP_PROTO_TCP:
            print("Layer 3 scan: TCP")
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            print("Layer 3 scan: UDP")
    
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