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
f = open('data/CaptureOne.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

# initilaze dictionaries for src and dst port counts
src_ports = {}
dst_ports = {}

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

    # icrement count for src and dst port
    if src_port in src_ports:
        src_ports[src_port] += 1
    else:
        src_ports[src_port] = 1

    if dst_port in dst_ports:
        dst_ports[dst_port] += 1
    else:
        dst_ports[dst_port] = 1

# sort the dictionaries by count in descending order
src_ports_sorted = {k: v for k, v in sorted(src_ports.items(), key=lambda item: item[1], reverse=True)}
dst_ports_sorted = {k: v for k, v in sorted(dst_ports.items(), key=lambda item: item[1], reverse=True)}

# print the top source ports
print("Top source ports:")
for port, count in src_ports_sorted.items():
    print(f"src_port: {port}, count: {count}")
    
# print the top destination ports
print("Top destination ports:")
for port, count in dst_ports_sorted.items():
    print(f"dst_port: {port}, count: {count}")