import dpkt
import socket

def tcp_traffic(src, dst):

    pcap_file = 'data/CaptureOne.pcap'
    src_ip = src
    dst_ip = dst
    print('number 2')
    print(src_ip, dst_ip)

    tcp_single_flow(pcap_file, src_ip, dst_ip)

# Create information for flows to anlyze if port scan, backscatter, Small SYN, one flow
def tcp_single_flow(pcap_file_path, src_ip, dst_ip):
    # Initialize data structures
    flows = {}

    # Open the pcap file
    with open(pcap_file_path, 'rb') as pcap_file:
        pcap_reader = dpkt.pcap.Reader(pcap_file)

        # Iterate through each packet in the pcap file
        for timestamp, packet_data in pcap_reader:
            eth_packet = dpkt.ethernet.Ethernet(packet_data)

            if not isinstance(eth_packet.data, dpkt.ip.IP) or not isinstance(eth_packet.data.data, dpkt.tcp.TCP):
                # Skip non-TCP packets
                continue

            ip_packet = eth_packet.data
            ip_src = socket.inet_ntoa(ip_packet.src)
            ip_dst = socket.inet_ntoa(ip_packet.dst)

            if ip_src != src_ip or ip_dst != dst_ip:
                # Skip packets that don't match the specified source and destination IP addresses
                continue
            print('number 3')
            print(src_ip, dst_ip)
            flow_key = (ip_src, ip_dst)

            # Check for flows that exists
            if flow_key in flows:
                # Update the flow information
                flow = flows[flow_key]
                flow['num_packets'] += 1
                flow['dst_ports'].add(ip_packet.data.dport)
            else: 
                print('hello')
                # Create new flows
                flow = {
                    'src_ip': ip_src,
                    'dst_ip': ip_dst,
                    'dst_ports': set(),
                    'num_packets': 1,
                    'scan_packets': 0,
                    'syn_packets': 0,
                    'frag_packets': 0
                }
            
                flows[flow_key] = flow

            # Update flags counters
            if ip_packet.data.flags & dpkt.tcp.TH_SYN:
                flow['scan_packets'] += 1
                flow['syn_packets'] += 1
            if ip_packet.data.flags & dpkt.tcp.TH_FIN:
                flow['scan_packets'] += 1
            if ip_packet.data.flags & dpkt.tcp.TH_FIN and ip_packet.data.flags & dpkt.tcp.TH_ACK:
                flow['scan_packets'] += 1
            if not ip_packet.data.flags:
                flow['scan_packets'] += 1

            # Check for fragmented packets
         #   if (ip_packet.data.off & dpkt.tcp.TCP_OFFMASK) != 0:
          #      flow['frag_packets'] += 1

        # Compute additional flow information and create a list of flow entries
        flow_list = []
        for flow_key, flow in flows.items():
            num_dst_ports = len(flow['dst_ports'])
            num_packets = flow['num_packets']
            scan_packets = flow['scan_packets']
            syn_packets = flow['syn_packets']
            frag_packets = flow['frag_packets']
            syn_pct = syn_packets / num_packets * 100 if num_packets > 0 else 0
            scan_pct = scan_packets / num_packets * 100 if num_packets > 0 else 0
            avg_packets_per_port = num_packets / num_dst_ports if num_dst_ports > 0 else 0

            # create flow entry and add to list
            flow_entry = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_ports': num_dst_ports,
                'num_packets': num_packets,
                'syn_percent': syn_pct,
                'scan_percent': scan_pct,
                'avg_packets_per_dst_port': avg_packets_per_port,
                'num_fragments': frag_packets
            }
            flow_list.append(flow_entry)

        # Return the flow list
        return flow_list




