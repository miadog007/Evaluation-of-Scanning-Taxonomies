import dpkt
import time
from collections import defaultdict

f = open('data/Using-Wireshark-diplay-filters-Emotet-with-IcedID.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

packet_count = 0
destination_count = set()
source_count = set()

for ts, buf in pcap:
    packet_count += 1
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    destination_count.add(ip.dst)
    source_count.add(ip.src)

breakdown = defaultdict(lambda: {'packet_count': 0, 'destination_count': set(), 'source_count': set()})

with open('data/Using-Wireshark-diplay-filters-Emotet-with-IcedID.pcap', 'rb') as f: 
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        date = time.strftime('%Y-%m-%d %H', time.gmtime(ts))
        breakdown[date]['packet_count'] += 1
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        breakdown[date]['destination_count'].add(ip.dst)
        breakdown[date]['source_count'].add(ip.src)


for date, counts in breakdown.items():
    print(f'{date}: {counts["packet_count"]} packets, {len(counts["destination_count"])} destinations, {len(counts["source_count"])} sources')