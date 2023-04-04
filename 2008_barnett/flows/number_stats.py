with open('icmp_one-to-one_barnett.txt', 'w') as f:
    f.write(f'Total icmp slow one-to-one src ips: {icmp_onetoone_slow}\n')
    f.write("---------------------\n")
    f.write(f'Total icmp medium one-to-one src ips: {icmp_onetoone_medium}\n')
    f.write("---------------------\n")
    f.write(f'Total icmp rapid one-to-one src ips: {icmp_onetoone_rapid}\n')

with open('icmp_onetomany_barnett.txt', 'w') as f:
    f.write(f'Total icmp slow one-to-one src ips: {icmp_onetomany_slow}\n')
    f.write("---------------------\n")
    f.write(f'Total icmp medium one-to-one src ips: {icmp_onetomany_medium}\n')
    f.write("---------------------\n")
    f.write(f'Total icmp rapid one-to-one src ips: {icmp_onetomany_rapid}\n')

with open('icmp_manytoone_barnett.txt', 'w') as f:
    f.write(f'Total icmp slow one-to-one src ips: {icmp_manytoone_slow}\n')
    f.write("---------------------\n")
    f.write(f'Total icmp medium one-to-one src ips: {icmp_manytoone_medium}\n')
    f.write("---------------------\n")
    f.write(f'Total icmp rapid one-to-one src ips: {icmp_manytoone_rapid}\n')

with open('icmp_manytomany_barnett.txt', 'w') as f:
    f.write(f'Total icmp slow one-to-one src ips: {icmp_manytomany_slow}\n')
    f.write("---------------------\n")
    f.write(f'Total icmp medium one-to-one src ips: {icmp_manytomany_medium}\n')
    f.write("---------------------\n")
    f.write(f'Total icmp rapid one-to-one src ips: {icmp_manytomany_rapid}\n')