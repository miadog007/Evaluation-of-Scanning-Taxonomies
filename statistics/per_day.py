import dpkt
import socket
from datetime import datetime

# Replace "example.pcap" with the name of your pcap file
with open('data/?', 'rb') as f, open("per_day_mar.txt", 'w') as outfile:
    pcap = dpkt.pcap.Reader(f)

    # Initialize variables to store daily packet and IP address counts
    current_day = None
    packets_count = 0
    ip_addresses = set()

    for ts, buf in pcap:
        # Convert the timestamp to a datetime object and get the day
        day = datetime.fromtimestamp(ts).date()

        # If the day has changed, outfile the counts for the previous day
        if current_day is not None and day != current_day:
            outfile.write(f"Day {current_day}:\n")
            outfile.write(f"  Packets: {packets_count}\n")
            outfile.write(f"  Unique IP addresses: {len(ip_addresses)}\n")
            outfile.write("\n")

            # Reset the counts for the new day
            packets_count = 0
            ip_addresses = set()

        # Parse the packet and extract the source and destination IP addresses
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)

        # Add the IP addresses to the set
        ip_addresses.add(src_ip)
        ip_addresses.add(dst_ip)

        # Increment the packet count
        packets_count += 1

        # Set the current day to the new day
        current_day = day

    # outfile the counts for the last day
    outfile.write(f"Day {current_day}:\n")
    outfile.write(f"  Packets: {packets_count}\n")
    outfile.write(f"  Unique IP addresses: {len(ip_addresses)}\n")
    outfile.write("\n")


