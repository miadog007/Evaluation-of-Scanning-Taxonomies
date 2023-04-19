import ast

# Fukuda files
# TCP
fukuda_tcp_light_port = 'Compare-scripts/fukuda/full-list/tcp_light_port_scans_fukuda.txt'
fukuda_tcp_light_network = 'Compare-scripts/fukuda/full-list/tcp_light_network_scans_fukuda.txt'
fukuda_tcp_heavy_network = 'Compare-scripts/fukuda/full-list/tcp_heavy_network_scans_fukuda.txt'
fukuda_tcp_oflow = 'Compare-scripts/fukuda/full-list/tcp_oflow_fukuda.txt'
fukuda_tcp_back = 'Compare-scripts/fukuda/full-list/tcp_back_fukuda.txt'
fukuda_tcp_small = 'Compare-scripts/fukuda/full-list/tcp_small_ip.txt'
fukuda_tcp_other = 'Compare-scripts/fukuda/full-list/tcp_other_ip.txt'

# UDP
fukuda_udp_port = 'Compare-scripts/fukuda/full-list/udp_port_fukuda.txt'
fukuda_udp_network = 'Compare-scripts/fukuda/full-list/udp_network_fukuda.txt'
fukuda_udp_oflow = 'Compare-scripts/fukuda/full-list/udp_oflow_fukuda.txt'
fukuda_udp_back = 'Compare-scripts/fukuda/full-list/udp_back_fukuda.txt'
fukuda_udp_small = 'Compare-scripts/fukuda/full-list/udp_small_ip.txt'
fukuda_udp_other = 'Compare-scripts/fukuda/full-list/udp_other_ip.txt'

# ICMP
fukuda_icmp_network = 'Compare-scripts/fukuda/full-list/icmp_network_fukuda.txt'
fukuda_icmp_back = 'Compare-scripts/fukuda/full-list/icmp_back_fukuda.txt'
fukuda_icmp_small = 'Compare-scripts/fukuda/full-list/icmp_small-ip.txt'

# Open the file containing the Python dict
dec = 'Compare-scripts/fukuda/full-list/tcp_light_network_scans_fukuda_dec.txt'
jan = 'Compare-scripts/fukuda/full-list/tcp_light_network_scans_fukuda_jan.txt'
feb = 'Compare-scripts/fukuda/full-list/udp_light_network_scans_fukuda_feb.txt'
mar = 'Compare-scripts/fukuda/full-list/udp_light_network_scans_fukuda_mar.txt'

feb_otm_slow_udp = 'Compare-scripts/barnett/full-list/udp_onetomany_slow_barnett_feb.txt'

udp_small = 'Compare-scripts/fukuda/full-list/udp_small_fukuda_mar.txt'

import ast

with open(mar, 'r') as f:
    data_str = f.read()
    data_dict = ast.literal_eval(data_str)
    
    counts = {}
    total_count = 0
    for key, value in data_dict.items():
        # for small lists
        second_part = value['dst_ports']
        if second_part in counts:
            counts[second_part] += 1
        else:
            counts[second_part] = 1
        total_count += 1
        
        # for network scan list
        """  second_part = key[1]
        if second_part in counts:
            counts[second_part] += 1
        else:
            counts[second_part] = 1
        total_count += 1 """
    
    top_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
    print('Top 10')
    for second_part, count in top_counts:
        print(f"{second_part}: {count}")
    
    print(f'Total: {total_count}')
