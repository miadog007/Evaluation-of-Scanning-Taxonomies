import dpkt
import socket


def inet_to_str(inet):
    """
    converts inet object to string

    args:
        inet (inet struct): inet network adress
    returns:
        str: printable/readable IP address
    """
    # Tries ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# open pcap for reding in dpkt
f = open('data/Using-Wireshark-diplay-filters-Emotet-with-IcedID.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

# initilaze dictionary for port pairing
port_pairing = {}

# iterate over packets
for ts, buf in pcap:

    eth = dpkt.ethernet.Ethernet(buf)

    #  Avoid ICMP packets
    if not isinstance(eth.data, dpkt.ip.IP):
        continue

    # extract ip pakcets
    ip = eth.data

    # extract to TCP packets
    tcp = ip.data

    # extract src and dst port numbers 
    src_port = tcp.sport
    dst_port = tcp.dport

    # extract port pairing in dicionary
    port_pairing[src_port] = dst_port

    # sort by src port in ascending order
    port_pairing_sorted = {k: v for k, v in sorted(port_pairing.items())}

    # count number of occurences of each port pairing
    pairing_count = {}
    for src_port, dst_port in port_pairing_sorted.items():
        pairing = (src_port, dst_port)
        if pairing in pairing_count:
            pairing_count[pairing] += 1
        else:
            pairing_count[pairing] = 1
    
    # sort the dictionary of port pairings and counts by count in descending order
    pairing_counts_sorted = {k: v for k, v in sorted(pairing_count.items(), key=lambda item: item[1], reverse=True)}
    
    # print port pairings and count of pairing
    for pairing, count in pairing_counts_sorted.items():
        src_port, dst_port = pairing
        print(f"source port: {src_port}, destination port: {dst_port}, count: {count}")
