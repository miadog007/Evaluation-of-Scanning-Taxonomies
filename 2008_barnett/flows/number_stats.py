# Old version counting number of flows instead of ip src's

print(f'Total tcp rapid src ips: {sum(val["ip_src_count"] for val in tcp_dist_rapid.values())}')
print(f'Total tcp rapid one-to-one src ips: {sum(val["ip_src_count"] for val in tcp_onetoone_rapid.values())}')
print(f'Total tcp rapid one-to-many src ips: {sum(val["ip_src_count"] for val in tcp_onetomany_rapid.values())}')
print(f'Total tcp rapid many-to-one src ips: {sum(val["ip_src_count"] for val in tcp_manytoone_rapid.values())}')
print(f'Total tcp rapid many-to-many src ips: {sum(val["ip_src_count"] for val in tcp_manytomany_rapid.values())}')