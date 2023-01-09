import dpkt
import socket

f = open('data/CaptureOne.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

dst_sizes = {}
src_sizes = {}

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

for ts, buf in pcap:
    
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data

    # Get dst and src IP
    dst = inet_to_str(ip.dst)
    src = inet_to_str(ip.src)

    # Get length of packet
    size = len(buf)

    if dst in dst_sizes:
        dst_sizes[dst] += size
    else:
        dst_sizes[dst] = size

    if src in src_sizes:
        src_sizes[src] += size
    else:
        src_sizes[src] = size

    # Sort the dst_sizes dictionary by size in descending order and print the results
sorted_dst_sizes = sorted(dst_sizes.items(), key=lambda x: x[1], reverse=True)
print(sorted_dst_sizes)

    # Sort the src_sizes dictionary by size in descending order and print the results
sorted_src_sizes = sorted(src_sizes.items(), key=lambda x: x[1], reverse=True)
print(sorted_src_sizes)


