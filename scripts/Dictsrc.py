import dpkt
import socket

# Ask user for number of sources to show
n_sources = input("Enter number of sources to show: ")

# convert user input to integer
n_sources = int(n_sources)

# Initialize counter 
counter = 0

# open pcap for reding in dpkt
f = open('data/CaptureOne.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)


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

# declarts a ip_counts dict
ip_counts ={}

for ts, buf in pcap:

    eth = dpkt.ethernet.Ethernet(buf)

    if not isinstance(eth.data, dpkt.ip.IP):
        continue

    ip = eth.data
    src_ip = inet_to_str(ip.src)

    if src_ip in ip_counts:
        ip_counts[src_ip] += 1
    else:
        ip_counts[src_ip] = 1


    # Printing Ip addresses and count in decending order.
for ip, count in sorted(ip_counts.items(), key=lambda item: item[1], reverse=True):
        # adds ip: IP_ADDRESS, count,: COUNT
    print(f"ip: {ip}, count: {count}")

    counter += 1

        # if counter equals number of sources specified, break loop
    if counter == n_sources:
        break
