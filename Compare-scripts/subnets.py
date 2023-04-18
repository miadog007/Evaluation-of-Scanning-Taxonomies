import ipaddress


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
fukuda_icmp_small = 'Compare-scripts/fukuda/ip_list/icmp_small-ip.txt'

# not working

with open(fukuda_tcp_network, 'r') as f:
        fukuda_ips = f.read().strip().replace(' ', '').split(',')

    # List of IP addresses
        ip_list = fukuda_ips


        unique_ips = set()

        unique_subnets = set()

        for ip in ip_list:
        
            ip_address = ipaddress.IPv4Address(ip)
            
            unique_ips.add(ip_address)
          
            network_address = ipaddress.ip_network(ip_address).network_address
            unique_subnets.add(network_address)

        print("Number of unique IP addresses:", len(unique_ips))
        print("Number of unique subnets:", len(unique_subnets))