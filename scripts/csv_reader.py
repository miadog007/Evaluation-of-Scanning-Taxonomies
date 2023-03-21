print('TCP slow stats')
print(f'Total TCP slow flows: {sum(len(keys) for keys in tcp_dist_slow)}')
print(f'Total tcp slow one-to-one flows: {sum(len(keys) for keys in tcp_onetoone_slow)}')
print(f'Total tcp slow one-to-many flows: {sum(len(keys) for keys in tcp_onetomany_slow)}')
print(f'Total tcp slow many-to-one flows: {sum(len(keys) for keys in tcp_manytoone_slow)}')
print(f'Total tcp slow many-to-many flows: {sum(len(keys) for keys in tcp_manytomany_slow)}')
print("---------------------")
print('slow TCP flows stats:')
print('slow one-to-one:')
print(f'tcp one-to-one slow other: {sum(len(keys) for keys in tcp_oto_slow)}')
print(f'tcp one-to-one slow SYN: {sum(len(keys) for keys in tcp_oto_slow_syn)}')
print(f'tcp one-to-one slow ACK: {sum(len(keys) for keys in tcp_oto_slow_ack)}')
print(f'tcp one-to-one slow FIN: {sum(len(keys) for keys in tcp_oto_slow_fin)}')
print('slow one-to-many:')
print(f'tcp one-to-many slow other: {sum(len(keys) for keys in tcp_otm_slow)}')
print(f'tcp one-to-many slow SYN: {sum(len(keys) for keys in tcp_otm_slow_syn)}')
print(f'tcp one-to-many slow ACK: {sum(len(keys) for keys in tcp_otm_slow_ack)}')
print(f'tcp one-to-many slow FIN: {sum(len(keys) for keys in tcp_otm_slow_fin)}')
print('slow many-to-one:')
print(f'tcp many-to-one slow other: {sum(len(keys) for keys in tcp_mto_slow)}')
print(f'tcp many-to-one slow SYN: {sum(len(keys) for keys in tcp_mto_slow_syn)}')
print(f'tcp many-to-one slow ACK: {sum(len(keys) for keys in tcp_mto_slow_ack)}')
print(f'tcp many-to-one slow FIN: {sum(len(keys) for keys in tcp_mto_slow_fin)}')
print('slow many-to-many:')
print(f'tcp many-to-many slow other: {sum(len(keys) for keys in tcp_mtm_slow)}')
print(f'tcp many-to-many slow SYN: {sum(len(keys) for keys in tcp_mtm_slow_syn)}')
print(f'tcp many-to-many slow ACK: {sum(len(keys) for keys in tcp_mtm_slow_ack)}')
print(f'tcp many-to-many slow FIN: {sum(len(keys) for keys in tcp_mtm_slow_fin)}')