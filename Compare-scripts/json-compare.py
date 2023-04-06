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

barnett_oto = 'Compare-scripts/barnett/ip_lists/tcp_onetoone_barnett.txt'
barnett_otm = 'Compare-scripts/barnett/ip_lists/tcp_onetomany_barnett.txt'
barnett_mto = 'Compare-scripts/barnett/ip_lists/tcp_manytoone_barnett.txt'
barnett_mtm = 'Compare-scripts/barnett/ip_lists/tcp_manytomany_barnett.txt'

fukuda_file = 'Compare-scripts/fukuda/ip_lists/icmp_other_fukuda.txt'

compare(barnett_oto, barnett_otm, barnett_mto, barnett_mtm, fukuda_file)

