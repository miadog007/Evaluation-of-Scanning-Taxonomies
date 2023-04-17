#print('slow TCP flows stats:')
#print('slow one-to-one:')
#print(f'TCP one-to-one slow other src ips: {sum(val["packet_count"] for val in tcp_oto_slow.values())}')
#print(f'TCP one-to-one slow SYN src ips: {sum(val["packet_count"] for val in tcp_oto_slow_syn.values())}')
#print(f'TCP one-to-one slow ACK src ips: {sum(val["packet_count"] for val in tcp_oto_slow_ack.values())}')
#print(f'TCP one-to-one slow FIN src ips: {sum(val["packet_count"] for val in tcp_oto_slow_fin.values())}')
#print('slow one-to-many:')
#print(f'TCP one-to-many slow other src ips: {sum(val["packet_count"] for val in tcp_otm_slow.values())}')
#print(f'TCP one-to-many slow SYN src ips: {sum(val["packet_count"] for val in tcp_otm_slow_syn.values())}')
#print(f'TCP one-to-many slow ACK src ips: {sum(val["packet_count"] for val in tcp_otm_slow_ack.values())}')
#print(f'TCP one-to-many slow FIN src ips: {sum(val["packet_count"] for val in tcp_otm_slow_fin.values())}')
#print('slow many-to-one:')
#print(f'TCP many-to-one slow other src ips: {sum(val["packet_count"] for val in tcp_mto_slow.values())}')
#print(f'TCP many-to-one slow SYN src ips: {sum(val["packet_count"] for val in tcp_mto_slow_syn.values())}')
#print(f'TCP many-to-one slow ACK src ips: {sum(val["packet_count"] for val in tcp_mto_slow_ack.values())}')
#print(f'TCP many-to-one slow FIN src ips: {sum(val["packet_count"] for val in tcp_mto_slow_fin.values())}')
#print('slow many-to-many:')
#print(f'TCP many-to-many slow other src ips: {sum(val["packet_count"] for val in tcp_mtm_slow.values())}')
#print(f'TCP many-to-many slow SYN src ips: {sum(val["packet_count"] for val in tcp_mtm_slow_syn.values())}')
#print(f'TCP many-to-many slow ACK src ips: {sum(val["packet_count"] for val in tcp_mtm_slow_ack.values())}')
#print(f'TCP many-to-many slow FIN src ips: {sum(val["packet_count"] for val in tcp_mtm_slow_fin.values())}')

#print('medium TCP flows stats:')
#print('medium one-to-one:')
#print(f'TCP one-to-one medium other src ips: {sum(val["packet_count"] for val in tcp_oto_medium.values())}')
#print(f'TCP one-to-one medium SYN src ips: {sum(val["packet_count"] for val in tcp_oto_medium_syn.values())}')
#print(f'TCP one-to-one medium ACK src ips: {sum(val["packet_count"] for val in tcp_oto_medium_ack.values())}')
#print(f'TCP one-to-one medium FIN src ips: {sum(val["packet_count"] for val in tcp_oto_medium_fin.values())}')
#print('medium one-to-many:')
#print(f'TCP one-to-many medium other src ips: {sum(val["packet_count"] for val in tcp_otm_medium.values())}')
#print(f'TCP one-to-many medium SYN src ips: {sum(val["packet_count"] for val in tcp_otm_medium_syn.values())}')
#print(f'TCP one-to-many medium ACK src ips: {sum(val["packet_count"] for val in tcp_otm_medium_ack.values())}')
#print(f'TCP one-to-many medium FIN src ips: {sum(val["packet_count"] for val in tcp_otm_medium_fin.values())}')
#print('medium many-to-one:')
#print(f'TCP many-to-one medium other src ips: {sum(val["packet_count"] for val in tcp_mto_medium.values())}')
#print(f'TCP many-to-one medium SYN src ips: {sum(val["packet_count"] for val in tcp_mto_medium_syn.values())}')
#print(f'TCP many-to-one medium ACK src ips: {sum(val["packet_count"] for val in tcp_mto_medium_ack.values())}')
#print(f'TCP many-to-one medium FIN src ips: {sum(val["packet_count"] for val in tcp_mto_medium_fin.values())}')
#print('medium many-to-many:')
#print(f'TCP many-to-many medium other src ips: {sum(val["packet_count"] for val in tcp_mtm_medium.values())}')
#print(f'TCP many-to-many medium SYN src ips: {sum(val["packet_count"] for val in tcp_mtm_medium_syn.values())}')
#print(f'TCP many-to-many medium ACK src ips: {sum(val["packet_count"] for val in tcp_mtm_medium_ack.values())}')
#print(f'TCP many-to-many medium FIN src ips: {sum(val["packet_count"] for val in tcp_mtm_medium_fin.values())}')

#print('Rapid TCP flows stats:')
#print('rapid one-to-one:')
#print(f'TCP one-to-one rapid other src ips: {sum(val["packet_count"] for val in tcp_oto_rapid.values())}')
#print(f'TCP one-to-one rapid SYN src ips: {sum(val["packet_count"] for val in tcp_oto_rapid_syn.values())}')
#print(f'TCP one-to-one rapid ACK src ips: {sum(val["packet_count"] for val in tcp_oto_rapid_ack.values())}')
#print(f'TCP one-to-one rapid FIN src ips: {sum(val["packet_count"] for val in tcp_oto_rapid_fin.values())}')
#print('rapid one-to-many:')
#print(f'TCP one-to-many rapid other src ips: {sum(val["packet_count"] for val in tcp_otm_rapid.values())}')
#print(f'TCP one-to-many rapid SYN src ips: {sum(val["packet_count"] for val in tcp_otm_rapid_syn.values())}')
#print(f'TCP one-to-many rapid ACK src ips: {sum(val["packet_count"] for val in tcp_otm_rapid_ack.values())}')
#print(f'TCP one-to-many rapid FIN src ips: {sum(val["packet_count"] for val in tcp_otm_rapid_fin.values())}')
#print('rapid many-to-one:')
#print(f'TCP many-to-one rapid other src ips: {sum(val["packet_count"] for val in tcp_mto_rapid.values())}')
#print(f'TCP many-to-one rapid SYN src ips: {sum(val["packet_count"] for val in tcp_mto_rapid_syn.values())}')
#print(f'TCP many-to-one rapid ACK src ips: {sum(val["packet_count"] for val in tcp_mto_rapid_ack.values())}')
#print(f'TCP many-to-one rapid FIN src ips: {sum(val["packet_count"] for val in tcp_mto_rapid_fin.values())}')
#print('rapid many-to-many:')
#print(f'TCP many-to-many rapid other src ips: {sum(val["packet_count"] for val in tcp_mtm_rapid.values())}')
#print(f'TCP many-to-many rapid SYN src ips: {sum(val["packet_count"] for val in tcp_mtm_rapid_syn.values())}')
#print(f'TCP many-to-many rapid ACK src ips: {sum(val["packet_count"] for val in tcp_mtm_rapid_ack.values())}')
#print(f'TCP many-to-many rapid FIN src ips: {sum(val["packet_count"] for val in tcp_mtm_rapid_fin.values())}')

""" from collections import Counter

dst_port_counter_slow = Counter()
print('tcp slow')
# Loop over the dictionary and update the counter with each dst port
for key, value in udp_onetomany_slow.items():
    dst_ports = value['dst_ports']
    for dst_port in dst_ports:
        if isinstance(dst_port, int):
            dst_port_counter_slow[dst_port] += 1
        else:
            for port in dst_port:
                dst_port_counter_slow[port] += 1
# Loop over the counter and print the dst ports with their corresponding counts
for dst_port, count_tcp_one_slow in dst_port_counter_slow.items():
    if count_tcp_one_slow > 1000: 
        print(f"dst_port {dst_port} is represented {count_tcp_one_slow} times")

dst_port_counter_medium = Counter()
print('tcp medium')
# Loop over the dictionary and update the counter with each dst port
for key, value in udp_onetomany_medium.items():
    dst_ports = value['dst_ports']
    for dst_port in dst_ports:
        if isinstance(dst_port, int):
            dst_port_counter_medium[dst_port] += 1
        else:
            for port in dst_port:
                dst_port_counter_medium[port] += 1
# Loop over the counter and print the dst ports with their corresponding counts
for dst_port, count_tcp_one_medium in dst_port_counter_medium.items():
    if count_tcp_one_medium > 1000: 
        print(f"dst_port {dst_port} is represented {count_tcp_one_medium} times")

dst_port_counter_rapid = Counter()
print('tcp rapid')
# Loop over the dictionary and update the counter with each dst port
for key, value in udp_onetomany_rapid.items():
    dst_ports = value['dst_ports']
    for dst_port in dst_ports:
        if isinstance(dst_port, int):
            dst_port_counter_rapid[dst_port] += 1
        else:
            for port in dst_port:
                dst_port_counter_rapid[port] += 1
# Loop over the counter and print the dst ports with their corresponding counts
for dst_port, count_tcp_one_rapid in dst_port_counter_rapid.items():
    if count_tcp_one_rapid > 1000: 
        print(f"dst_port {dst_port} is represented {count_tcp_one_rapid} times") """

# One to one lists
values = [*tcp_onetoone_slow.values()]
tcp_oto_src_slow_ips = set(tuple(entry['src_ips']) for entry in values)
tcp_oto_slow = [ip[0] for ip in tcp_oto_src_slow_ips]
tcp_oto_slow_f = ', '.join(tcp_oto_slow)

values = [*tcp_onetoone_medium.values()]
tcp_oto_src_medium_ips = set(tuple(entry['src_ips']) for entry in values)
tcp_oto_medium = [ip[0] for ip in tcp_oto_src_medium_ips]
tcp_oto_medium_f = ', '.join(tcp_oto_medium)

values = [*tcp_onetoone_rapid.values()]
tcp_oto_src_rapid_ips = set(tuple(entry['src_ips']) for entry in values)
tcp_oto_rapid = [ip[0] for ip in tcp_oto_src_rapid_ips]
tcp_oto_rapid_f = ', '.join(tcp_oto_rapid)

with open('ip-list/tcp_onetoone_slow_barnett.txt', 'w') as f:
    f.write(tcp_oto_slow_f)
with open('ip-list/tcp_onetoone_medium_barnett.txt', 'w') as f:
    f.write(tcp_oto_medium_f)
with open('ip-list/tcp_onetoone_rapid_barnett.txt', 'w') as f:
    f.write(tcp_oto_rapid_f)

values = [*udp_onetoone_slow.values()]
udp_oto_src_slow_ips = set(tuple(entry['src_ips']) for entry in values)
udp_oto_slow = [ip[0] for ip in udp_oto_src_slow_ips]
udp_oto_slow_f = ', '.join(udp_oto_slow)

values = [*udp_onetoone_medium.values()]
udp_oto_src_medium_ips = set(tuple(entry['src_ips']) for entry in values)
udp_oto_medium = [ip[0] for ip in udp_oto_src_medium_ips]
udp_oto_medium_f = ', '.join(udp_oto_medium)

values = [*udp_onetoone_rapid.values()]
udp_oto_src_rapid_ips = set(tuple(entry['src_ips']) for entry in values)
udp_oto_rapid = [ip[0] for ip in udp_oto_src_rapid_ips]
udp_oto_rapid_f = ', '.join(udp_oto_rapid)

with open('ip-list/udp_onetoone_slow_barnett.txt', 'w') as f:
    f.write(udp_oto_slow_f)
with open('ip-list/udp_onetoone_medium_barnett.txt', 'w') as f:
    f.write(udp_oto_medium_f)
with open('ip-list/udp_onetoone_rapid_barnett.txt', 'w') as f:
    f.write(udp_oto_rapid_f)

values = [*icmp_onetoone_slow.values()]
icmp_oto_src_slow_ips = set(tuple(entry['src_ips']) for entry in values)
icmp_oto_slow = [ip[0] for ip in icmp_oto_src_slow_ips]
icmp_oto_slow_f = ', '.join(icmp_oto_slow)

values = [*icmp_onetoone_medium.values()]
icmp_oto_src_medium_ips = set(tuple(entry['src_ips']) for entry in values)
icmp_oto_medium = [ip[0] for ip in icmp_oto_src_medium_ips]
icmp_oto_medium_f = ', '.join(icmp_oto_medium)

values = [*icmp_onetoone_rapid.values()]
icmp_oto_src_rapid_ips = set(tuple(entry['src_ips']) for entry in values)
icmp_oto_rapid = [ip[0] for ip in icmp_oto_src_rapid_ips]
icmp_oto_rapid_f = ', '.join(icmp_oto_rapid)

with open('ip-list/icmp_onetoone_slow_barnett.txt', 'w') as f:
    f.write(icmp_oto_slow_f)
with open('ip-list/icmp_onetoone_medium_barnett.txt', 'w') as f:
    f.write(icmp_oto_medium_f)
with open('ip-list/icmp_onetoone_rapid_barnett.txt', 'w') as f:
    f.write(icmp_oto_rapid_f)


# one to many lists
values = [*tcp_onetomany_slow.values()]
tcp_otm_src_slow_ips = set(tuple(entry['src_ips']) for entry in values)
tcp_otm_slow = [ip[0] for ip in tcp_otm_src_slow_ips]
tcp_otm_slow_f = ', '.join(tcp_otm_slow)

values = [*tcp_onetomany_medium.values()]
tcp_otm_src_medium_ips = set(tuple(entry['src_ips']) for entry in values)
tcp_otm_medium = [ip[0] for ip in tcp_otm_src_medium_ips]
tcp_otm_medium_f = ', '.join(tcp_otm_medium)

values = [*tcp_onetomany_rapid.values()]
tcp_otm_src_rapid_ips = set(tuple(entry['src_ips']) for entry in values)
tcp_otm_rapid = [ip[0] for ip in tcp_otm_src_rapid_ips]
tcp_otm_rapid_f = ', '.join(tcp_otm_rapid)

with open('ip-list/tcp_onetomany_slow_barnett.txt', 'w') as f:
    f.write(tcp_otm_slow_f)
with open('ip-list/tcp_onetomany_medium_barnett.txt', 'w') as f:
    f.write(tcp_otm_medium_f)
with open('ip-list/tcp_onetomany_rapid_barnett.txt', 'w') as f:
    f.write(tcp_otm_rapid_f)

values = [*udp_onetomany_slow.values()]
udp_otm_src_slow_ips = set(tuple(entry['src_ips']) for entry in values)
udp_otm_slow = [ip[0] for ip in udp_otm_src_slow_ips]
udp_otm_slow_f = ', '.join(udp_otm_slow)

values = [*udp_onetomany_medium.values()]
udp_otm_src_medium_ips = set(tuple(entry['src_ips']) for entry in values)
udp_otm_medium = [ip[0] for ip in udp_otm_src_medium_ips]
udp_otm_medium_f = ', '.join(udp_otm_medium)

values = [*udp_onetomany_rapid.values()]
udp_otm_src_rapid_ips = set(tuple(entry['src_ips']) for entry in values)
udp_otm_rapid = [ip[0] for ip in udp_otm_src_rapid_ips]
udp_otm_rapid_f = ', '.join(udp_otm_rapid)

with open('ip-list/udp_onetomany_slow_barnett.txt', 'w') as f:
    f.write(udp_otm_slow_f)
with open('ip-list/udp_onetomany_medium_barnett.txt', 'w') as f:
    f.write(udp_otm_medium_f)
with open('ip-list/udp_onetomany_rapid_barnett.txt', 'w') as f:
    f.write(udp_otm_rapid_f)

values = [*icmp_onetomany_slow.values()]
icmp_otm_src_slow_ips = set(tuple(entry['src_ips']) for entry in values)
icmp_otm_slow = [ip[0] for ip in icmp_otm_src_slow_ips]
icmp_otm_slow_f = ', '.join(icmp_otm_slow)

values = [*icmp_onetomany_medium.values()]
icmp_otm_src_medium_ips = set(tuple(entry['src_ips']) for entry in values)
icmp_otm_medium = [ip[0] for ip in icmp_otm_src_medium_ips]
icmp_otm_medium_f = ', '.join(icmp_otm_medium)

values = [*icmp_onetomany_rapid.values()]
icmp_otm_src_rapid_ips = set(tuple(entry['src_ips']) for entry in values)
icmp_otm_rapid = [ip[0] for ip in icmp_otm_src_rapid_ips]
icmp_otm_rapid_f = ', '.join(icmp_otm_rapid)

with open('ip-list/icmp_onetomany_slow_barnett.txt', 'w') as f:
    f.write(icmp_otm_slow_f)
with open('ip-list/icmp_onetomany_medium_barnett.txt', 'w') as f:
    f.write(icmp_otm_medium_f)
with open('ip-list/icmp_onetomany_rapid_barnett.txt', 'w') as f:
    f.write(icmp_otm_rapid_f)

# many to one list
values = [*tcp_manytoone_slow.values()]
tcp_mto_src_slow_ips = set(tuple(entry['src_ips']) for entry in values)
tcp_mto_slow = [ip[0] for ip in tcp_mto_src_slow_ips]
tcp_mto_slow_f = ', '.join(tcp_mto_slow)

values = [*tcp_manytoone_medium.values()]
tcp_mto_src_medium_ips = set(tuple(entry['src_ips']) for entry in values)
tcp_mto_medium = [ip[0] for ip in tcp_mto_src_medium_ips]
tcp_mto_medium_f = ', '.join(tcp_mto_medium)

values = [*tcp_manytoone_rapid.values()]
tcp_mto_src_rapid_ips = set(tuple(entry['src_ips']) for entry in values)
tcp_mto_rapid = [ip[0] for ip in tcp_mto_src_rapid_ips]
tcp_mto_rapid_f = ', '.join(tcp_mto_rapid)

with open('ip-list/tcp_manytoone_slow_barnett.txt', 'w') as f:
    f.write(tcp_mto_slow_f)
with open('ip-list/tcp_manytoone_medium_barnett.txt', 'w') as f:
    f.write(tcp_mto_medium_f)
with open('ip-list/tcp_manytoone_rapid_barnett.txt', 'w') as f:
    f.write(tcp_mto_rapid_f)

values = [*udp_manytoone_slow.values()]
udp_mto_src_slow_ips = set(tuple(entry['src_ips']) for entry in values)
udp_mto_slow = [ip[0] for ip in udp_mto_src_slow_ips]
udp_mto_slow_f = ', '.join(udp_mto_slow)

values = [*udp_manytoone_medium.values()]
udp_mto_src_medium_ips = set(tuple(entry['src_ips']) for entry in values)
udp_mto_medium = [ip[0] for ip in udp_mto_src_medium_ips]
udp_mto_medium_f = ', '.join(udp_mto_medium)

values = [*udp_manytoone_rapid.values()]
udp_mto_src_rapid_ips = set(tuple(entry['src_ips']) for entry in values)
udp_mto_rapid = [ip[0] for ip in udp_mto_src_rapid_ips]
udp_mto_rapid_f = ', '.join(udp_mto_rapid)

with open('ip-list/udp_manytoone_slow_barnett.txt', 'w') as f:
    f.write(udp_mto_slow_f)
with open('ip-list/udp_manytoone_medium_barnett.txt', 'w') as f:
    f.write(udp_mto_medium_f)
with open('ip-list/udp_manytoone_rapid_barnett.txt', 'w') as f:
    f.write(udp_mto_rapid_f)

values = [*icmp_manytoone_slow.values()]
icmp_mto_src_slow_ips = set(tuple(entry['src_ips']) for entry in values)
icmp_mto_slow = [ip[0] for ip in icmp_mto_src_slow_ips]
icmp_mto_slow_f = ', '.join(icmp_mto_slow)

values = [*icmp_manytoone_medium.values()]
icmp_mto_src_medium_ips = set(tuple(entry['src_ips']) for entry in values)
icmp_mto_medium = [ip[0] for ip in icmp_mto_src_medium_ips]
icmp_mto_medium_f = ', '.join(icmp_mto_medium)

values = [*icmp_manytoone_rapid.values()]
icmp_mto_src_rapid_ips = set(tuple(entry['src_ips']) for entry in values)
icmp_mto_rapid = [ip[0] for ip in icmp_mto_src_rapid_ips]
icmp_mto_rapid_f = ', '.join(icmp_mto_rapid)

with open('ip-list/icmp_manytoone_slow_barnett.txt', 'w') as f:
    f.write(icmp_mto_slow_f)
with open('ip-list/icmp_manytoone_medium_barnett.txt', 'w') as f:
    f.write(icmp_mto_medium_f)
with open('ip-list/icmp_manytoone_rapid_barnett.txt', 'w') as f:
    f.write(icmp_mto_rapid_f)

# many to many lists
values = [*tcp_manytomany_slow.values()]
tcp_mtm_src_slow_ips = set(tuple(entry['src_ips']) for entry in values)
tcp_mtm_slow = [ip[0] for ip in tcp_mtm_src_slow_ips]
tcp_mtm_slow_f = ', '.join(tcp_mtm_slow)

values = [*tcp_manytomany_medium.values()]
tcp_mtm_src_medium_ips = set(tuple(entry['src_ips']) for entry in values)
tcp_mtm_medium = [ip[0] for ip in tcp_mtm_src_medium_ips]
tcp_mtm_medium_f = ', '.join(tcp_mtm_medium)

values = [*tcp_manytomany_rapid.values()]
tcp_mtm_src_rapid_ips = set(tuple(entry['src_ips']) for entry in values)
tcp_mtm_rapid = [ip[0] for ip in tcp_mtm_src_rapid_ips]
tcp_mtm_rapid_f = ', '.join(tcp_mtm_rapid)

with open('ip-list/tcp_manytomany_slow_barnett.txt', 'w') as f:
    f.write(tcp_mtm_slow_f)
with open('ip-list/tcp_manytomany_medium_barnett.txt', 'w') as f:
    f.write(tcp_mtm_medium_f)
with open('ip-list/tcp_manytomany_rapid_barnett.txt', 'w') as f:
    f.write(tcp_mtm_rapid_f)

values = [*udp_manytomany_slow.values()]
udp_mtm_src_slow_ips = set(tuple(entry['src_ips']) for entry in values)
udp_mtm_slow = [ip[0] for ip in udp_mtm_src_slow_ips]
udp_mtm_slow_f = ', '.join(udp_mtm_slow)

values = [*udp_manytomany_medium.values()]
udp_mtm_src_medium_ips = set(tuple(entry['src_ips']) for entry in values)
udp_mtm_medium = [ip[0] for ip in udp_mtm_src_medium_ips]
udp_mtm_medium_f = ', '.join(udp_mtm_medium)

values = [*udp_manytomany_rapid.values()]
udp_mtm_src_rapid_ips = set(tuple(entry['src_ips']) for entry in values)
udp_mtm_rapid = [ip[0] for ip in udp_mtm_src_rapid_ips]
udp_mtm_rapid_f = ', '.join(udp_mtm_rapid)

with open('ip-list/udp_manytomany_slow_barnett.txt', 'w') as f:
    f.write(udp_mtm_slow_f)
with open('ip-list/udp_manytomany_medium_barnett.txt', 'w') as f:
    f.write(udp_mtm_medium_f)
with open('ip-list/udp_manytomany_rapid_barnett.txt', 'w') as f:
    f.write(udp_mtm_rapid_f)

values = [*icmp_manytomany_slow.values()]
icmp_mtm_src_slow_ips = set(tuple(entry['src_ips']) for entry in values)
icmp_mtm_slow = [ip[0] for ip in icmp_mtm_src_slow_ips]
icmp_mtm_slow_f = ', '.join(icmp_mtm_slow)

values = [*icmp_manytomany_medium.values()]
icmp_mtm_src_medium_ips = set(tuple(entry['src_ips']) for entry in values)
icmp_mtm_medium = [ip[0] for ip in icmp_mtm_src_medium_ips]
icmp_mtm_medium_f = ', '.join(icmp_mtm_medium)

values = [*icmp_manytomany_rapid.values()]
icmp_mtm_src_rapid_ips = set(tuple(entry['src_ips']) for entry in values)
icmp_mtm_rapid = [ip[0] for ip in icmp_mtm_src_rapid_ips]
icmp_mtm_rapid_f = ', '.join(icmp_mtm_rapid)

with open('ip-list/icmp_manytomany_slow_barnett.txt', 'w') as f:
    f.write(icmp_mtm_slow_f)
with open('ip-list/icmp_manytomany_medium_barnett.txt', 'w') as f:
    f.write(icmp_mtm_medium_f)
with open('ip-list/icmp_manytomany_rapid_barnett.txt', 'w') as f:
    f.write(icmp_mtm_rapid_f)


port_counts = {}
for key in tcp_onetomany_slow.keys():
    if key[1] != 'many':
        port = key[1]
        if port in port_counts:
            port_counts[port] += 1
        else:
            port_counts[port] = 1

for port, count in port_counts.items():
    if port_counts[port] > 1000:
        print(f"Port {port} has {count} keys that are not 'many'")

print('one to one')
port_counts = {}
for key in tcp_onetoone_rapid.keys():
    if key[1] != 'many':
        port = key[1]
        if port in port_counts:
            port_counts[port] += 1
        else:
            port_counts[port] = 1

for port, count in port_counts.items():
    if port_counts[port] > 1000:
        print(f"Port {port} has {count} keys that are not 'many'")

""" for val in tcp_onetomany_medium.values():
    if val['src_ips'] == '119.45.157.33':
       print(val['packet_count'])
 """

"""
for key, val in tcp_onetomany_rapid.items():
    if sum(len(port_range) for port_range in val['dst_ports']) > 1:
        print(key) 

for key, val in udp_manytoone_rapid.items():
    if sum(len(port_range) for port_range in val['dst_ports']) > 1:
        print(key)

for key, val in tcp_manytomany_rapid.items():
    if sum(len(port_range) for port_range in val['dst_ports']) > 1:
        print(key) 

for key, val in udp_manytomany_rapid.items():
    if sum(len(port_range) for port_range in val['dst_ports']) > 1:
        print(key)

# Print out values and count for one-to-many
for key, value in tcp_onetomany_slow.items():
    if '51.255.81.155' in value['src_ips']:
        print(len(key), sum(len(port_range) for port_range in value['dst_ports']), value['src_ips'], value['packet_count']) """

""" print(' check for 193.122.96.137 ')
for key, value in tcp_onetoone_slow.items():
    if '193.122.96.137' in value['src_ips']:
        print(len(key), sum(len(port_range) for port_range in value['dst_ports']), value['src_ips'], value['packet_count'])
for key, value in tcp_onetoone_medium.items():
    if '193.122.96.137' in value['src_ips']:
        print(len(key), sum(len(port_range) for port_range in value['dst_ports']), value['src_ips'], value['packet_count'])
for key, value in tcp_onetoone_rapid.items():
    if '193.122.96.137' in value['src_ips']:
        print(len(key), sum(len(port_range) for port_range in value['dst_ports']), value['src_ips'], value['packet_count'])
 """
#with open('tcp_many-ports-check_barnett.txt', 'w') as f:
    #f.write(f'Total TCP slow one-to-one src ips: {tcp_onetoone_rapid}\n')
  #  f.write("---------------------\n")
   # f.write(f'Total TCP slow one-to-many src ips: {tcp_onetomany_rapid}\n')
    #f.write("---------------------\n")
 #   f.write(f'Total TCP slow many-to-one src ips: {tcp_manytoone_rapid}\n')
    #f.write("---------------------\n")
  #  f.write(f'Total TCP slow many-to-many src ips: {tcp_manytomany_rapid}\n')


# Get full dicts

""" with open('full-list/tcp_onetoone_slow_barnett.txt', 'w') as f:
    f.write(str(tcp_onetoone_slow))
with open('full-list/tcp_onetoone_medium_barnett.txt', 'w') as f:
    f.write(str(tcp_onetoone_medium))
with open('full-list/tcp_onetoone_rapid_barnett.txt', 'w') as f:
    f.write(str(tcp_onetoone_rapid)) 

with open('full-list/tcp_manytoone_slow_barnett.txt', 'w') as f:
    f.write(str(tcp_manytoone_slow))
with open('full-list/tcp_manytoone_medium_barnett.txt', 'w') as f:
    f.write(str(tcp_manytoone_medium))
with open('full-list/tcp_manytoone_rapid_barnett.txt', 'w') as f:
    f.write(str(tcp_manytoone_rapid)) 

with open('full-list/tcp_onetomany_slow_barnett.txt', 'w') as f:
    f.write(str(tcp_onetomany_slow))
with open('full-list/tcp_onetomany_medium_barnett.txt', 'w') as f:
    f.write(str(tcp_onetomany_medium))
with open('full-list/tcp_onetomany_rapid_barnett.txt', 'w') as f:
    f.write(str(tcp_onetomany_rapid)) 

with open('full-list/tcp_manytomany_slow_barnett.txt', 'w') as f:
    f.write(str(tcp_manytomany_slow))
with open('full-list/tcp_manytomany_medium_barnett.txt', 'w') as f:
    f.write(str(tcp_manytomany_medium))
with open('full-list/tcp_manytomany_rapid_barnett.txt', 'w') as f:
    f.write(str(tcp_manytomany_rapid)) 

with open('full-list/udp_onetoone_slow_barnett.txt', 'w') as f:
    f.write(str(udp_onetoone_slow))
with open('full-list/udp_onetoone_medium_barnett.txt', 'w') as f:
    f.write(str(udp_onetoone_medium))
with open('full-list/udp_onetoone_rapid_barnett.txt', 'w') as f:
    f.write(str(udp_onetoone_rapid)) 

with open('full-list/udp_manytoone_slow_barnett.txt', 'w') as f:
    f.write(str(udp_manytoone_slow))
with open('full-list/udp_manytoone_medium_barnett.txt', 'w') as f:
    f.write(str(udp_manytoone_medium))
with open('full-list/udp_manytoone_rapid_barnett.txt', 'w') as f:
    f.write(str(udp_manytoone_rapid)) 

with open('full-list/udp_onetomany_slow_barnett.txt', 'w') as f:
    f.write(str(udp_onetomany_slow))
with open('full-list/udp_onetomany_medium_barnett.txt', 'w') as f:
    f.write(str(udp_onetomany_medium))
with open('full-list/udp_onetomany_rapid_barnett.txt', 'w') as f:
    f.write(str(udp_onetomany_rapid)) 

with open('full-list/udp_manytomany_slow_barnett.txt', 'w') as f:
    f.write(str(udp_manytomany_slow))
with open('full-list/udp_manytomany_medium_barnett.txt', 'w') as f:
    f.write(str(udp_manytomany_medium))
with open('full-list/udp_manytomany_rapid_barnett.txt', 'w') as f:
    f.write(str(udp_manytomany_rapid)) 

with open('full-list/icmp_onetoone_slow_barnett.txt', 'w') as f:
    f.write(str(icmp_onetoone_slow))
with open('full-list/icmp_onetoone_medium_barnett.txt', 'w') as f:
    f.write(str(icmp_onetoone_medium))
with open('full-list/icmp_onetoone_rapid_barnett.txt', 'w') as f:
    f.write(str(icmp_onetoone_rapid)) 

with open('full-list/icmp_manytoone_slow_barnett.txt', 'w') as f:
    f.write(str(icmp_manytoone_slow))
with open('full-list/icmp_manytoone_medium_barnett.txt', 'w') as f:
    f.write(str(icmp_manytoone_medium))
with open('full-list/icmp_manytoone_rapid_barnett.txt', 'w') as f:
    f.write(str(icmp_manytoone_rapid)) 

with open('full-list/icmp_onetomany_slow_barnett.txt', 'w') as f:
    f.write(str(icmp_onetomany_slow))
with open('full-list/icmp_onetomany_medium_barnett.txt', 'w') as f:
    f.write(str(icmp_onetomany_medium))
with open('full-list/icmp_onetomany_rapid_barnett.txt', 'w') as f:
    f.write(str(icmp_onetomany_rapid)) 

with open('full-list/icmp_manytomany_slow_barnett.txt', 'w') as f:
    f.write(str(icmp_manytomany_slow))
with open('full-list/icmp_manytomany_medium_barnett.txt', 'w') as f:
    f.write(str(icmp_manytomany_medium))
with open('full-list/icmp_manytomany_rapid_barnett.txt', 'w') as f:
    f.write(str(icmp_manytomany_rapid))  """

""" 
with open('december_packet_barnett.txt', 'a') as f:
    f.write("---------------------\n")
    f.write('PCAP info:\n')
    f.write(f'Number of packets: {total_packets}\n')
    f.write(f'Total Source IPs: {len(ip_src)}\n')
    f.write(f'Labled source ips: {labled_sources}\n')
    f.write("---------------------\n")
    f.write("---------------------\n")
    f.write("TCP\n")
    f.write(f'Total TCP flows: {len(tcp_flows.keys())}\n')
    f.write(f'TCP Uniqe IP src: {len(tcp_src)}\n')
    f.write(f'TCP packets: {tcp_packets}\n')
    f.write("---------------------\n")
    f.write('TCP slow stats\n')
    f.write(f'Total TCP slow src ips: {sum(val["packet_count"] for val in tcp_dist_slow.values())}\n')
    f.write(f'Total TCP slow one-to-one src ips: {sum(val["packet_count"] for val in tcp_onetoone_slow.values())}\n')
    f.write(f'Total TCP slow one-to-many src ips: {sum(val["packet_count"] for val in tcp_onetomany_slow.values())}\n')
    f.write(f'Total TCP slow many-to-one src ips: {sum(val["packet_count"] for val in tcp_manytoone_slow.values())}\n')
    f.write(f'Total TCP slow many-to-many src ips: {sum(val["packet_count"] for val in tcp_manytomany_slow.values())}\n')
    f.write("---------------------\n")
    f.write('TCP medium stats\n')
    f.write(f'Total tcp medium src ips: {sum(val["packet_count"] for val in tcp_dist_medium.values())}\n')
    f.write(f'Total tcp medium one-to-one src ips: {sum(val["packet_count"] for val in tcp_onetoone_medium.values())}\n')
    f.write(f'Total tcp medium one-to-many src ips: {sum(val["packet_count"] for val in tcp_onetomany_medium.values())}\n')
    f.write(f'Total tcp medium many-to-one src ips: {sum(val["packet_count"] for val in tcp_manytoone_medium.values())}\n')
    f.write(f'Total tcp medium many-to-many src ips: {sum(val["packet_count"] for val in tcp_manytomany_medium.values())}\n')
    f.write("---------------------\n")
    f.write('TCP Rapid stats\n')
    f.write(f'Total tcp rapid src ips: {sum(val["packet_count"] for val in tcp_dist_rapid.values())}\n')
    f.write(f'Total tcp rapid one-to-one src ips: {sum(val["packet_count"] for val in tcp_onetoone_rapid.values())}\n')
    f.write(f'Total tcp rapid one-to-many src ips: {sum(val["packet_count"] for val in tcp_onetomany_rapid.values())}\n')
    f.write(f'Total tcp rapid many-to-one src ips: {sum(val["packet_count"] for val in tcp_manytoone_rapid.values())}\n')
    f.write(f'Total tcp rapid many-to-many src ips: {sum(val["packet_count"] for val in tcp_manytomany_rapid.values())}\n')
    f.write("---------------------\n")
    f.write("---------------------\n")
    f.write("---------------------\n")
    f.write("UDP\n")
    f.write(f'Total UDP flows: {len(udp_flows.keys())}\n')
    f.write(f'UDP Uniqe IP src: {len(udp_src)}\n')
    f.write(f'UDP packets: {udp_packets}\n')
    f.write("---------------------\n")
    f.write('UDP slow stats\n')
    f.write(f'Total udp slow src ips: {sum(val["packet_count"] for val in udp_dist_slow.values())}\n')
    f.write(f'Total udp slow one-to-one src ips: {sum(val["packet_count"] for val in udp_onetoone_slow.values())}\n')
    f.write(f'Total udp slow one-to-many src ips: {sum(val["packet_count"] for val in udp_onetomany_slow.values())}\n')
    f.write(f'Total udp slow many-to-one src ips: {sum(val["packet_count"] for val in udp_manytoone_slow.values())}\n')
    f.write(f'Total udp slow many-to-many src ips: {sum(val["packet_count"] for val in udp_manytomany_slow.values())}\n')
    f.write("---------------------\n")
    f.write('UDP Medium stats\n')
    f.write(f'Total udp medium src ips: {sum(val["packet_count"] for val in udp_dist_medium.values())}\n')
    f.write(f'Total udp medium one-to-one src ips: {sum(val["packet_count"] for val in udp_onetoone_medium.values())}\n')
    f.write(f'Total udp medium one-to-many src ips: {sum(val["packet_count"] for val in udp_onetomany_medium.values())}\n')
    f.write(f'Total udp medium many-to-one src ips: {sum(val["packet_count"] for val in udp_manytoone_medium.values())}\n')
    f.write(f'Total udp medium many-to-many src ips: {sum(val["packet_count"] for val in udp_manytomany_medium.values())}\n')
    f.write("---------------------\n")
    f.write('UDP Rapid stats\n')
    f.write(f'Total udp rapid src ips: {sum(val["packet_count"] for val in udp_dist_rapid.values())}\n')
    f.write(f'Total udp rapid one-to-one src ips: {sum(val["packet_count"] for val in udp_onetoone_rapid.values())}\n')
    f.write(f'Total udp rapid one-to-many src ips: {sum(val["packet_count"] for val in udp_onetomany_rapid.values())}\n')
    f.write(f'Total udp rapid many-to-one src ips: {sum(val["packet_count"] for val in udp_manytoone_rapid.values())}\n')
    f.write(f'Total udp rapid many-to-many src ips: {sum(val["packet_count"] for val in udp_manytomany_rapid.values())}\n')
    f.write("---------------------\n")
    f.write("---------------------\n")
    f.write("---------------------\n") 
    f.write("ICMP\n")
    f.write(f'Total ICMP flows: {len(icmp_flows.keys())}\n')
    f.write(f'ICMP Uniqe IP src: {len(icmp_src)}\n')
    f.write(f'ICMP packets: {icmp_packets}\n')
    f.write("---------------------\n")
    f.write('ICMP slow stats\n')
    f.write(f'Total icmp slow src ips: {sum(val["packet_count"] for val in icmp_dist_slow.values())}\n')
    f.write(f'Total icmp slow one-to-one src ips: {sum(val["packet_count"] for val in icmp_onetoone_slow.values())}\n')
    f.write(f'Total icmp slow one-to-many src ips: {sum(val["packet_count"] for val in icmp_onetomany_slow.values())}\n')
    f.write(f'Total icmp slow many-to-one src ips: {sum(val["packet_count"] for val in icmp_manytoone_slow.values())}\n')
    f.write(f'Total icmp slow many-to-many src ips: {sum(val["packet_count"] for val in icmp_manytomany_slow.values())}\n')
    f.write("---------------------\n")
    f.write('ICMP Medium stats\n')
    f.write(f'Total icmp medium src ips: {sum(val["packet_count"] for val in icmp_dist_medium.values())}\n')
    f.write(f'Total icmp medium one-to-one src ips: {sum(val["packet_count"] for val in icmp_onetoone_medium.values())}\n')
    f.write(f'Total icmp medium one-to-many src ips: {sum(val["packet_count"] for val in icmp_onetomany_medium.values())}\n')
    f.write(f'Total icmp medium many-to-one src ips: {sum(val["packet_count"] for val in icmp_manytoone_medium.values())}\n')
    f.write(f'Total icmp medium many-to-many src ips: {sum(val["packet_count"] for val in icmp_manytomany_medium.values())}\n')
    f.write("---------------------\n")
    f.write('ICMP Rapid stats\n')
    f.write(f'Total icmp rapid src ips: {sum(val["packet_count"] for val in icmp_dist_rapid.values())}\n')
    f.write(f'Total icmp rapid one-to-one src ips: {sum(val["packet_count"] for val in icmp_onetoone_rapid.values())}\n')
    f.write(f'Total icmp rapid one-to-many src ips: {sum(val["packet_count"] for val in icmp_onetomany_rapid.values())}\n')
    f.write(f'Total icmp rapid many-to-one src ips: {sum(val["packet_count"] for val in icmp_manytoone_rapid.values())}\n')
    f.write(f'Total icmp rapid many-to-many src ips: {sum(val["packet_count"] for val in icmp_manytomany_rapid.values())}\n')
    f.write("---------------------\n")
    f.write(f'Other traffic: {other}\n')
    f.write("---------------------\n") """