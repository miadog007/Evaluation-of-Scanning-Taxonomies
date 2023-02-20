import socket
import dpkt

pcap_file = 'data/CaptureOne.pcap'

# parameters
M = 3
R = 50
N1 = 5 
N2 = 5
N3 = 15

# TCP port scan analysis
def analyze_tcp_port_scan(pcap_file):

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        # Dictionary dst port
        port_counts = collections.defaultdict(int)

        # Dictionary SYN
        syn_counts = collections.defaultdict(int)

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data

            # number of packets for each destination port
            port_counts[tcp.dport] += 1

            # SYN packets for each destination port
            if (tcp.flags & dpkt.tcp.TH_SYN) != 0:
                syn_counts[tcp.dport] += 1

        # heavy or light
        for port, count in port_counts.items():
            scan_flag_ratio = syn_counts[port] / count * 100

            # TCP heavy scan
            if (ip.src == ip.dst == socket.inet_aton('127.0.0.1')) and (port >= N2) and (scan_flag_ratio >= R) and (count > M):
                print(f'TCP heavy scan detected on port {port}')

            # TCP light scan
            elif (ip.src == ip.dst == socket.inet_aton('127.0.0.1')) and (port >= N2) and (scan_flag_ratio >= R) and (count <= M):
                print(f'TCP light scan detected on port {port}')


