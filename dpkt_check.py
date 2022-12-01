import dpkt
import socket


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


# Write source IP's for every packet
with open('anon_196.21.146.cap', 'rb') as dump:
    for time_stamp, payload in dpkt.pcap.Reader(dump):
        eth = dpkt.ethernet.Ethernet(payload)
        print("{:15}\t{:5}\t{:15}\t{:5}".format(
            inet_to_str(eth.data.src),
            str(eth.data.data.sport),
            inet_to_str(eth.data.dst),
            str(eth.data.data.dport)))

# ERROR if icmp
