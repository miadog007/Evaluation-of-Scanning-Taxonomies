import dpkt
import socket

tflows = {}
uflows = {}
iflows = {}
ips = set()

for ts, pkt in dpkt.pcap.Reader(open('data/Using-Wireshark-diplay-filters-Emotet-with-IcedID.pcap', 'rb')):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data

    # determine transport layer type
    if isinstance(ip, dpkt.ip.IP):
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            flows = tflows
        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            flows = uflows
        elif ip.p == dpkt.ip.IP_PROTO_ICMP:
            flows = iflows
        else:
            flows = {}

        # extract IP and transport layer data
        src_ip = socket.inet_ntoa(ip.src)
        src_port = ip.data.sport
        dst_ip = socket.inet_ntoa(ip.dst)
        dst_port = ip.data.dport
        proto = ip.p  # IP protocol information

        # keeping set of unique IPs
        ips.add(src_ip)
        ips.add(dst_ip)

        # store flow data
        flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        flow = (flow[0], flow[1])
        flow_data = {
            'byte_count': len(eth),
            'ts': ts,
            'dst_port': dst_port
        }

        if flows.get(flow):
            flows[flow].append(flow_data)
        else:
            flows[flow] = [flow_data]

        # extract TCP/UDP/ICMP specific information
        if proto == dpkt.ip.IP_PROTO_TCP:
            flags = dpkt.tcp.tcp_flags_to_str(ip.data.flags)
            # add TCP specific information to the flow data dictionary
            flow_data['flags'] = flags
        elif proto == dpkt.ip.IP_PROTO_UDP:
            # add UDP specific information to the flow data dictionary
            pass
        elif proto == dpkt.ip.IP_PROTO_ICMP:
            type_code = ip.data.type << 8 | ip.data.code
            # add ICMP specific information to the flow data dictionary
            flow_data['type_code'] = type_code

        for flow, packets in flows.items():
            proto = flow[0]
            src_ip = flow[0][0]
            dst_ip = flow[1][0]
            src_port = flow[0][1] if proto != dpkt.ip.IP_PROTO_ICMP else None
            dst_port = flow[1][1]

            packets_per_port = {}
            for pkt in packets:
                dst_port = pkt['dst_port']
                if dst_port in packets_per_port:
                    packets_per_port[dst_port] += 1
                else:
                    packets_per_port[dst_port] = 1

                flags = pkt.get('flags')
                type_code = pkt.get('type_code')

        for dst_port, packet_count in packets_per_port.items():
            print(f'Flow Info: {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}')
            print(f'\tIP Src: {src_ip}')
            print(f'\tIP Dst: {dst_ip}')
            print(f'\tPort Src: {src_port}')
            print(f'\tPort Dst: {dst_port}')
            print(f'\tNumber of packets: {packet_count}')
            if flags:
                print(f'\tScan flags: {flags}')
            if type_code:
                print(f'\tType code: {type_code}')
            print('')
