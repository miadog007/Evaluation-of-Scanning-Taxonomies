def compare(barnett_oto, barnett_otm, barnett_mto, barnett_mtm, fukuda_file):
        # Read the fukuda file
    with open(fukuda_file, 'r') as f:
        fukuda_ips = f.read().strip().split(',')

    # Read the barnett files
    with open(barnett_oto, 'r') as f1:
        oto_ips = f1.read().strip().split(',')

    with open(barnett_otm, 'r') as f2:
        otm_ips = f2.read().strip().split(',')

    with open(barnett_mto, 'r') as f3:
        mto_ips = f3.read().strip().split(',')
        
    with open(barnett_mtm, 'r') as f4:
        mtm_ips = f4.read().strip().split(',')

    # Find the number of src_ips from the fukuda represented in the barnett files
    count_oto_otm = len(set(otm_ips).intersection(set(oto_ips)))
    count_oto_mto = len(set(mto_ips).intersection(set(oto_ips)))
    count_oto_mtm = len(set(mtm_ips).intersection(set(oto_ips)))
    count_otm_oto = len(set(oto_ips).intersection(set(otm_ips)))
    count_mto = len(set(fukuda_ips).intersection(set(mto_ips)))
    count_mtm = len(set(fukuda_ips).intersection(set(mtm_ips)))

    print(count_oto_otm)
    print(count_otm_oto)
 
    """ with open('ICMP_compare.txt', 'a') as file:
        file.write(f'Total ICMP other uniqe ips in fukuda: {len(fukuda_ips)}\n')
        file.write(f'Ips in One-to-One: {count_oto}\n')
        file.write(f'Ips in One-to-Many: {count_otm}\n')
        file.write(f'Ips in Many-to-One: {count_mto}\n')
        file.write(f'Ips in Many-to-Many: {count_mtm}\n' )
        file.write('------------------------\n')
 """

# Barnet files
# TCP
barnett_oto_slow_tcp = 'Compare-scripts/barnett/ip_lists/tcp_onetoone_slow_barnett.txt'
barnett_oto_medium_tcp = 'Compare-scripts/barnett/ip_lists/tcp_onetoone_medium_barnett.txt'
barnett_oto_rapid_tcp = 'Compare-scripts/barnett/ip_lists/tcp_onetoone_rapid_barnett.txt'

barnett_otm_slow_tcp = 'Compare-scripts/barnett/ip_lists/tcp_onetomany_slow_barnett.txt'
barnett_otm_medium_tcp = 'Compare-scripts/barnett/ip_lists/tcp_onetomany_medium_barnett.txt'
barnett_otm_rapid_tcp = 'Compare-scripts/barnett/ip_lists/tcp_onetomany_rapid_barnett.txt'

barnett_mto_slow_tcp = 'Compare-scripts/barnett/ip_lists/tcp_manytoone_slow_barnett.txt'
barnett_mto_medium_tcp = 'Compare-scripts/barnett/ip_lists/tcp_manytoone_medium_barnett.txt'
barnett_mto_rapid_tcp = 'Compare-scripts/barnett/ip_lists/tcp_manytoone_rapid_barnett.txt'

barnett_mtm_slow_tcp = 'Compare-scripts/barnett/ip_lists/tcp_manytomany_slow_barnett.txt'
barnett_mtm_medium_tcp = 'Compare-scripts/barnett/ip_lists/tcp_manytomany_medium_barnett.txt'
barnett_mtm_rapid_tcp = 'Compare-scripts/barnett/ip_lists/tcp_manytomany_rapid_barnett.txt'

# UDP
barnett_oto_slow_udp = 'Compare-scripts/barnett/ip_lists/udp_onetoone_slow_barnett.txt'
barnett_oto_medium_udp = 'Compare-scripts/barnett/ip_lists/udp_onetoone_medium_barnett.txt'
barnett_oto_rapid_udp = 'Compare-scripts/barnett/ip_lists/udp_onetoone_rapid_barnett.txt'

barnett_otm_slow_udp = 'Compare-scripts/barnett/ip_lists/udp_onetomany_slow_barnett.txt'
barnett_otm_medium_udp = 'Compare-scripts/barnett/ip_lists/udp_onetomany_medium_barnett.txt'
barnett_otm_rapid_udp = 'Compare-scripts/barnett/ip_lists/udp_onetomany_rapid_barnett.txt'

barnett_mto_slow_udp = 'Compare-scripts/barnett/ip_lists/udp_manytoone_slow_barnett.txt'
barnett_mto_medium_udp = 'Compare-scripts/barnett/ip_lists/udp_manytoone_medium_barnett.txt'
barnett_mto_rapid_udp = 'Compare-scripts/barnett/ip_lists/udp_manytoone_rapid_barnett.txt'

barnett_mtm_slow_udp = 'Compare-scripts/barnett/ip_lists/udp_manytomany_slow_barnett.txt'
barnett_mtm_medium_udp = 'Compare-scripts/barnett/ip_lists/udp_manytomany_medium_barnett.txt'
barnett_mtm_rapid_udp = 'Compare-scripts/barnett/ip_lists/udp_manytomany_rapid_barnett.txt'
# ICMP
barnett_oto_slow_icmp = 'Compare-scripts/barnett/ip_lists/icmp_onetoone_slow_barnett.txt'
barnett_oto_medium_icmp = 'Compare-scripts/barnett/ip_lists/icmp_onetoone_medium_barnett.txt'
barnett_oto_rapid_icmp = 'Compare-scripts/barnett/ip_lists/icmp_onetoone_rapid_barnett.txt'

barnett_otm_slow_icmp = 'Compare-scripts/barnett/ip_lists/icmp_onetomany_slow_barnett.txt'
barnett_otm_medium_icmp = 'Compare-scripts/barnett/ip_lists/icmp_onetomany_medium_barnett.txt'
barnett_otm_rapid_icmp = 'Compare-scripts/barnett/ip_lists/icmp_onetomany_rapid_barnett.txt'

barnett_mto_slow_icmp = 'Compare-scripts/barnett/ip_lists/icmp_manytoone_slow_barnett.txt'
barnett_mto_medium_icmp = 'Compare-scripts/barnett/ip_lists/icmp_manytoone_medium_barnett.txt'
barnett_mto_rapid_icmp = 'Compare-scripts/barnett/ip_lists/icmp_manytoone_rapid_barnett.txt'

barnett_mtm_slow_icmp = 'Compare-scripts/barnett/ip_lists/icmp_manytomany_slow_barnett.txt'
barnett_mtm_medium_icmp = 'Compare-scripts/barnett/ip_lists/icmp_manytomany_medium_barnett.txt'
barnett_mtm_rapid_icmp = 'Compare-scripts/barnett/ip_lists/icmp_manytomany_rapid_barnett.txt'

# Fukuda files
fukuda_file = 'Compare-scripts/fukuda/ip_lists/icmp_other_fukuda.txt'



compare(barnett_oto, barnett_otm, barnett_mto, barnett_mtm, fukuda_file)

