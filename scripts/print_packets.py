import dpkt
import datetime
import socket

f = open('anon_196.21.146.cap', 'rb')
pcap = dpkt.pcap.Reader(f)


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def top_src(): #Not done
    for buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        print(ip.src)


for ts, buf in pcap:

    print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(ts)))
    eth = dpkt.ethernet.Ethernet(buf)

    if not isinstance(eth.data, dpkt.ip.IP):
        print('No IP')
        continue

    ip = eth.data

    if isinstance(ip.data, dpkt.icmp. ICMP):
        icmp = ip.data
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        print('Packet: %s-> %s (len=%d ttl=%d DF=%d MF=%d offset=%d)' % \
                       (inet_to_str(ip.src), inet_to_str(ip.dst),
                        ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))
        print('ICMP: type:%d code:%d checksum:%d data:%s\n' % \
                     (icmp.type, icmp.code, icmp.sum, repr(icmp.data)))

    else:
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        print('Packet: %s:%s-> %s:%s (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
                  (inet_to_str(ip.src), eth.data.data.sport, inet_to_str(ip.dst),
                   eth.data.data.dport, ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))
