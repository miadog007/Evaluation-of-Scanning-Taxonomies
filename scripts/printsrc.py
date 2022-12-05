import dpkt
import datetime
import socket
from functools import reduce

f = open('data/CaptureOne.pcap', 'rb')
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

countsrc = []

for ts, buf in pcap:

    eth = dpkt.ethernet.Ethernet(buf)

    if not isinstance(eth.data, dpkt.ip.IP):
        print('No IP')
        continue

    ip = eth.data

    countsrc.append(inet_to_str(ip.src))
    
def indexof(list, ip):
    for idx,item in enumerate(list):
        if item["ip"] == ip:
            return idx
    return -1

def count(reducelist, newIp):
    index = indexof(reducelist, newIp)
    if index != -1:
        reducelist[index] = {"ip": newIp, "count": reducelist[index]["count"]+1}
    else:
        reducelist.append({"ip": newIp, "count": 1})
    return reducelist

preduce=reduce(count, countsrc, [])
for elem in preduce:
    print(elem) 