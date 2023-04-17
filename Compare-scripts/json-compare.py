def compare(barnett_slow, barnett_medium, barnett_rapid, fukuda_file, anomaly_fuk, anomaly_bar):
    # Read the fukuda file
    with open(fukuda_file, 'r') as f:
        fukuda_ips = f.read().strip().split(',')

    # Read the barnett files
    with open(barnett_slow, 'r') as f1:
        slow = f1.read().strip().split(',')

    with open(barnett_medium, 'r') as f2:
        medium = f2.read().strip().split(',')

    with open(barnett_rapid, 'r') as f3:
        rapid = f3.read().strip().split(',')

    # Find the number of src_ips from the fukuda represented in the barnett files
    fukuda_ips_count = len(fukuda_ips)
    slow_count = len(slow)
    medium_count = len(medium)
    rapid_count = len(rapid)

    count_slow = len(set(slow).intersection(set(fukuda_ips)))
    count_medium = len(set(medium).intersection(set(fukuda_ips)))
    count_rapid = len(set(rapid).intersection(set(fukuda_ips)))

    with open(f'{anomaly_fuk}.txt', 'a') as file:
        file.write(f'{anomaly_bar}\n')
        file.write(
            f'Total ICMP other uniqe ips in fukuda: {fukuda_ips_count}\n')
        file.write(f'Ips in Slow: {slow_count}\n')
        file.write(f'Ips in Slow and {anomaly_fuk}: {count_slow}\n')
        file.write('------------------------\n')
        file.write(f'Ips in Medium: {medium_count}\n')
        file.write(f'Ips in Medium and {anomaly_fuk}: {count_medium}\n')
        file.write('------------------------\n')
        file.write(f'Ips in Rapid: {rapid_count}\n')
        file.write(f'Ips in Rapid and {anomaly_fuk}: {count_rapid}\n')
        file.write('------------------------\n')
        file.write('------------------------\n')




# Barnet files
# TCP
barnett_oto_slow_tcp = 'Compare-scripts/barnett/ip_list/tcp_onetoone_slow_barnett.txt'
barnett_oto_medium_tcp = 'Compare-scripts/barnett/ip_list/tcp_onetoone_medium_barnett.txt'
barnett_oto_rapid_tcp = 'Compare-scripts/barnett/ip_list/tcp_onetoone_rapid_barnett.txt'

barnett_otm_slow_tcp = 'Compare-scripts/barnett/ip_list/tcp_onetomany_slow_barnett.txt'
barnett_otm_medium_tcp = 'Compare-scripts/barnett/ip_list/tcp_onetomany_medium_barnett.txt'
barnett_otm_rapid_tcp = 'Compare-scripts/barnett/ip_list/tcp_onetomany_rapid_barnett.txt'

barnett_mto_slow_tcp = 'Compare-scripts/barnett/ip_list/tcp_manytoone_slow_barnett.txt'
barnett_mto_medium_tcp = 'Compare-scripts/barnett/ip_list/tcp_manytoone_medium_barnett.txt'
barnett_mto_rapid_tcp = 'Compare-scripts/barnett/ip_list/tcp_manytoone_rapid_barnett.txt'

barnett_mtm_slow_tcp = 'Compare-scripts/barnett/ip_list/tcp_manytomany_slow_barnett.txt'
barnett_mtm_medium_tcp = 'Compare-scripts/barnett/ip_list/tcp_manytomany_medium_barnett.txt'
barnett_mtm_rapid_tcp = 'Compare-scripts/barnett/ip_list/tcp_manytomany_rapid_barnett.txt'

# UDP
barnett_oto_slow_udp = 'Compare-scripts/barnett/ip_list/udp_onetoone_slow_barnett.txt'
barnett_oto_medium_udp = 'Compare-scripts/barnett/ip_list/udp_onetoone_medium_barnett.txt'
barnett_oto_rapid_udp = 'Compare-scripts/barnett/ip_list/udp_onetoone_rapid_barnett.txt'

barnett_otm_slow_udp = 'Compare-scripts/barnett/ip_list/udp_onetomany_slow_barnett.txt'
barnett_otm_medium_udp = 'Compare-scripts/barnett/ip_list/udp_onetomany_medium_barnett.txt'
barnett_otm_rapid_udp = 'Compare-scripts/barnett/ip_list/udp_onetomany_rapid_barnett.txt'

barnett_mto_slow_udp = 'Compare-scripts/barnett/ip_list/udp_manytoone_slow_barnett.txt'
barnett_mto_medium_udp = 'Compare-scripts/barnett/ip_list/udp_manytoone_medium_barnett.txt'
barnett_mto_rapid_udp = 'Compare-scripts/barnett/ip_list/udp_manytoone_rapid_barnett.txt'

barnett_mtm_slow_udp = 'Compare-scripts/barnett/ip_list/udp_manytomany_slow_barnett.txt'
barnett_mtm_medium_udp = 'Compare-scripts/barnett/ip_list/udp_manytomany_medium_barnett.txt'
barnett_mtm_rapid_udp = 'Compare-scripts/barnett/ip_list/udp_manytomany_rapid_barnett.txt'
# ICMP
barnett_oto_slow_icmp = 'Compare-scripts/barnett/ip_list/icmp_onetoone_slow_barnett.txt'
barnett_oto_medium_icmp = 'Compare-scripts/barnett/ip_list/icmp_onetoone_medium_barnett.txt'
barnett_oto_rapid_icmp = 'Compare-scripts/barnett/ip_list/icmp_onetoone_rapid_barnett.txt'

barnett_otm_slow_icmp = 'Compare-scripts/barnett/ip_list/icmp_onetomany_slow_barnett.txt'
barnett_otm_medium_icmp = 'Compare-scripts/barnett/ip_list/icmp_onetomany_medium_barnett.txt'
barnett_otm_rapid_icmp = 'Compare-scripts/barnett/ip_list/icmp_onetomany_rapid_barnett.txt'

barnett_mto_slow_icmp = 'Compare-scripts/barnett/ip_list/icmp_manytoone_slow_barnett.txt'
barnett_mto_medium_icmp = 'Compare-scripts/barnett/ip_list/icmp_manytoone_medium_barnett.txt'
barnett_mto_rapid_icmp = 'Compare-scripts/barnett/ip_list/icmp_manytoone_rapid_barnett.txt'

barnett_mtm_slow_icmp = 'Compare-scripts/barnett/ip_list/icmp_manytomany_slow_barnett.txt'
barnett_mtm_medium_icmp = 'Compare-scripts/barnett/ip_list/icmp_manytomany_medium_barnett.txt'
barnett_mtm_rapid_icmp = 'Compare-scripts/barnett/ip_list/icmp_manytomany_rapid_barnett.txt'

# Fukuda files
# TCP
fukuda_tcp_port = 'Compare-scripts/fukuda/ip_list/tcp_port_fukuda.txt'
fukuda_tcp_network = 'Compare-scripts/fukuda/ip_list/tcp_network_fukuda.txt'
fukuda_tcp_oflow = 'Compare-scripts/fukuda/ip_list/tcp_oflow_fukuda.txt'
fukuda_tcp_back = 'Compare-scripts/fukuda/ip_list/tcp_back_fukuda.txt'
fukuda_tcp_small = 'Compare-scripts/fukuda/ip_list/tcp_small_ip.txt'
fukuda_tcp_other = 'Compare-scripts/fukuda/ip_list/tcp_other_ip.txt'

# UDP
fukuda_udp_port = 'Compare-scripts/fukuda/ip_list/udp_port_fukuda.txt'
fukuda_udp_network = 'Compare-scripts/fukuda/ip_list/udp_network_fukuda.txt'
fukuda_udp_oflow = 'Compare-scripts/fukuda/ip_list/udp_oflow_fukuda.txt'
fukuda_udp_back = 'Compare-scripts/fukuda/ip_list/udp_back_fukuda.txt'
fukuda_udp_small = 'Compare-scripts/fukuda/ip_list/udp_small_ip.txt'
fukuda_udp_other = 'Compare-scripts/fukuda/ip_list/udp_other_ip.txt'

# ICMP
fukuda_icmp_network = 'Compare-scripts/fukuda/ip_list/icmp_network_fukuda.txt'
fukuda_icmp_back = 'Compare-scripts/fukuda/ip_list/icmp_back_fukuda.txt'
fukuda_icmp_small = 'Compare-scripts/fukuda/ip_list/icmp_small_ip.txt'

# TCP comparions
# Port
compare(barnett_oto_slow_tcp, barnett_oto_medium_tcp,
        barnett_oto_rapid_tcp, fukuda_tcp_port, 'tcp-port', 'one-to-one')
compare(barnett_otm_slow_tcp, barnett_otm_medium_tcp,
        barnett_otm_rapid_tcp, fukuda_tcp_port, 'tcp-port', 'one-to-many')
compare(barnett_mto_slow_tcp, barnett_mto_medium_tcp,
        barnett_mto_rapid_tcp, fukuda_tcp_port, 'tcp-port', 'many-to-one')
compare(barnett_mtm_slow_tcp, barnett_mtm_medium_tcp,
        barnett_mtm_rapid_tcp, fukuda_tcp_port, 'tcp-port', 'many-to-many')

# Network
compare(barnett_oto_slow_tcp, barnett_oto_medium_tcp,
        barnett_oto_rapid_tcp, fukuda_tcp_network, 'tcp-network', 'one-to-one')
compare(barnett_otm_slow_tcp, barnett_otm_medium_tcp,
        barnett_otm_rapid_tcp, fukuda_tcp_network, 'tcp-network', 'one-to-many')
compare(barnett_mto_slow_tcp, barnett_mto_medium_tcp,
        barnett_mto_rapid_tcp, fukuda_tcp_network, 'tcp-network', 'many-to-one')
compare(barnett_mtm_slow_tcp, barnett_mtm_medium_tcp,
        barnett_mtm_rapid_tcp, fukuda_tcp_network, 'tcp-network', 'many-to-many')

# One flow
compare(barnett_oto_slow_tcp, barnett_oto_medium_tcp,
        barnett_oto_rapid_tcp, fukuda_tcp_oflow, 'tcp-oflow', 'one-to-one')
compare(barnett_otm_slow_tcp, barnett_otm_medium_tcp,
        barnett_otm_rapid_tcp, fukuda_tcp_oflow, 'tcp-oflow', 'one-to-many')
compare(barnett_mto_slow_tcp, barnett_mto_medium_tcp,
        barnett_mto_rapid_tcp, fukuda_tcp_oflow, 'tcp-oflow', 'many-to-one')
compare(barnett_mtm_slow_tcp, barnett_mtm_medium_tcp,
        barnett_mtm_rapid_tcp, fukuda_tcp_oflow, 'tcp-oflow', 'many-to-many')

# Backscatter
compare(barnett_oto_slow_tcp, barnett_oto_medium_tcp,
        barnett_oto_rapid_tcp, fukuda_tcp_back, 'tcp-back', 'one-to-one')
compare(barnett_otm_slow_tcp, barnett_otm_medium_tcp,
        barnett_otm_rapid_tcp, fukuda_tcp_back, 'tcp-back', 'one-to-many')
compare(barnett_mto_slow_tcp, barnett_mto_medium_tcp,
        barnett_mto_rapid_tcp, fukuda_tcp_back, 'tcp-back', 'many-to-one')
compare(barnett_mtm_slow_tcp, barnett_mtm_medium_tcp,
        barnett_mtm_rapid_tcp, fukuda_tcp_back, 'tcp-back', 'many-to-many')

# Small
compare(barnett_oto_slow_tcp, barnett_oto_medium_tcp,
        barnett_oto_rapid_tcp, fukuda_tcp_small, 'tcp-small', 'one-to-one')
compare(barnett_otm_slow_tcp, barnett_otm_medium_tcp,
        barnett_otm_rapid_tcp, fukuda_tcp_small, 'tcp-small', 'one-to-many')
compare(barnett_mto_slow_tcp, barnett_mto_medium_tcp,
        barnett_mto_rapid_tcp, fukuda_tcp_small, 'tcp-small', 'many-to-one')
compare(barnett_mtm_slow_tcp, barnett_mtm_medium_tcp,
        barnett_mtm_rapid_tcp, fukuda_tcp_small, 'tcp-small', 'many-to-many')

# Other
compare(barnett_oto_slow_tcp, barnett_oto_medium_tcp,
        barnett_oto_rapid_tcp, fukuda_tcp_other, 'tcp-other', 'one-to-one')
compare(barnett_otm_slow_tcp, barnett_otm_medium_tcp,
        barnett_otm_rapid_tcp, fukuda_tcp_other, 'tcp-other', 'one-to-many')
compare(barnett_mto_slow_tcp, barnett_mto_medium_tcp,
        barnett_mto_rapid_tcp, fukuda_tcp_other, 'tcp-other', 'many-to-one')
compare(barnett_mtm_slow_tcp, barnett_mtm_medium_tcp,
        barnett_mtm_rapid_tcp, fukuda_tcp_other, 'tcp-other', 'many-to-many')

# UDP comparisons
# Port
compare(barnett_oto_slow_udp, barnett_oto_medium_udp,
        barnett_oto_rapid_udp, fukuda_udp_port, 'udp-port', 'one-to-one')
compare(barnett_otm_slow_udp, barnett_otm_medium_udp,
        barnett_otm_rapid_udp, fukuda_udp_port, 'udp-port', 'one-to-many')
compare(barnett_mto_slow_udp, barnett_mto_medium_udp,
        barnett_mto_rapid_udp, fukuda_udp_port, 'udp-port', 'many-to-one')
compare(barnett_mtm_slow_udp, barnett_mtm_medium_udp,
        barnett_mtm_rapid_udp, fukuda_udp_port, 'udp-port', 'many-to-many')

# Network
compare(barnett_oto_slow_udp, barnett_oto_medium_udp,
        barnett_oto_rapid_udp, fukuda_udp_network, 'udp-network', 'one-to-one')
compare(barnett_otm_slow_udp, barnett_otm_medium_udp,
        barnett_otm_rapid_udp, fukuda_udp_network, 'udp-network', 'one-to-many')
compare(barnett_mto_slow_udp, barnett_mto_medium_udp,
        barnett_mto_rapid_udp, fukuda_udp_network, 'udp-network', 'many-to-one')
compare(barnett_mtm_slow_udp, barnett_mtm_medium_udp,
        barnett_mtm_rapid_udp, fukuda_udp_network, 'udp-network', 'many-to-many')

# One flow
compare(barnett_oto_slow_udp, barnett_oto_medium_udp,
        barnett_oto_rapid_udp, fukuda_udp_oflow, 'udp-oflow', 'one-to-one')
compare(barnett_otm_slow_udp, barnett_otm_medium_udp,
        barnett_otm_rapid_udp, fukuda_udp_oflow, 'udp-oflow', 'one-to-many')
compare(barnett_mto_slow_udp, barnett_mto_medium_udp,
        barnett_mto_rapid_udp, fukuda_udp_oflow, 'udp-oflow', 'many-to-one')
compare(barnett_mtm_slow_udp, barnett_mtm_medium_udp,
        barnett_mtm_rapid_udp, fukuda_udp_oflow, 'udp-oflow', 'many-to-many')

# Backscatter
compare(barnett_oto_slow_udp, barnett_oto_medium_udp,
        barnett_oto_rapid_udp, fukuda_udp_back, 'udp-back', 'one-to-one')
compare(barnett_otm_slow_udp, barnett_otm_medium_udp,
        barnett_otm_rapid_udp, fukuda_udp_back, 'udp-back', 'one-to-many')
compare(barnett_mto_slow_udp, barnett_mto_medium_udp,
        barnett_mto_rapid_udp, fukuda_udp_back, 'udp-back', 'many-to-one')
compare(barnett_mtm_slow_udp, barnett_mtm_medium_udp,
        barnett_mtm_rapid_udp, fukuda_udp_back, 'udp-back', 'many-to-many')

# Small
compare(barnett_oto_slow_udp, barnett_oto_medium_udp,
        barnett_oto_rapid_udp, fukuda_udp_small, 'udp-small', 'one-to-one')
compare(barnett_otm_slow_udp, barnett_otm_medium_udp,
        barnett_otm_rapid_udp, fukuda_udp_small, 'udp-small', 'one-to-many')
compare(barnett_mto_slow_udp, barnett_mto_medium_udp,
        barnett_mto_rapid_udp, fukuda_udp_small, 'udp-small', 'many-to-one')
compare(barnett_mtm_slow_udp, barnett_mtm_medium_udp,
        barnett_mtm_rapid_udp, fukuda_udp_small, 'udp-small', 'many-to-many')

# Other
compare(barnett_oto_slow_udp, barnett_oto_medium_udp,
        barnett_oto_rapid_udp, fukuda_udp_other, 'udp-other', 'one-to-one')
compare(barnett_otm_slow_udp, barnett_otm_medium_udp,
        barnett_otm_rapid_udp, fukuda_udp_other, 'udp-other', 'one-to-many')
compare(barnett_mto_slow_udp, barnett_mto_medium_udp,
        barnett_mto_rapid_udp, fukuda_udp_other, 'udp-other', 'many-to-one')
compare(barnett_mtm_slow_udp, barnett_mtm_medium_udp,
        barnett_mtm_rapid_udp, fukuda_udp_other, 'udp-other', 'many-to-many')

# ICMP comparions
# Network
compare(barnett_oto_slow_icmp, barnett_oto_medium_icmp,
        barnett_oto_rapid_icmp, fukuda_icmp_network, 'icmp-network', 'one-to-one')
compare(barnett_otm_slow_icmp, barnett_otm_medium_icmp,
        barnett_otm_rapid_icmp, fukuda_icmp_network, 'icmp-network', 'one-to-many')
compare(barnett_mto_slow_icmp, barnett_mto_medium_icmp,
        barnett_mto_rapid_icmp, fukuda_icmp_network, 'icmp-network', 'many-to-one')
compare(barnett_mtm_slow_icmp, barnett_mtm_medium_icmp,
        barnett_mtm_rapid_icmp, fukuda_icmp_network, 'icmp-network', 'many-to-many')

# Backscatter
compare(barnett_oto_slow_icmp, barnett_oto_medium_icmp,
        barnett_oto_rapid_icmp, fukuda_icmp_back, 'icmp-back', 'one-to-one')
compare(barnett_otm_slow_icmp, barnett_otm_medium_icmp,
        barnett_otm_rapid_icmp, fukuda_icmp_back, 'icmp-back', 'one-to-many')
compare(barnett_mto_slow_icmp, barnett_mto_medium_icmp,
        barnett_mto_rapid_icmp, fukuda_icmp_back, 'icmp-back', 'many-to-one')
compare(barnett_mtm_slow_icmp, barnett_mtm_medium_icmp,
        barnett_mtm_rapid_icmp, fukuda_icmp_back, 'icmp-back', 'many-to-many')

# Small
compare(barnett_oto_slow_icmp, barnett_oto_medium_icmp,
        barnett_oto_rapid_icmp, fukuda_icmp_small, 'icmp-small', 'one-to-one')
compare(barnett_otm_slow_icmp, barnett_otm_medium_icmp,
        barnett_otm_rapid_icmp, fukuda_icmp_small, 'icmp-small', 'one-to-many')
compare(barnett_mto_slow_icmp, barnett_mto_medium_icmp,
        barnett_mto_rapid_icmp, fukuda_icmp_small, 'icmp-small', 'many-to-one')
compare(barnett_mtm_slow_icmp, barnett_mtm_medium_icmp,
        barnett_mtm_rapid_icmp, fukuda_icmp_small, 'icmp-small', 'many-to-many')
