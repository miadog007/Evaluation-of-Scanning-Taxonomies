# icmp flows
icmp_flows = {}

# icmp dist step 1
icmp_compare = {}

# icmp speed checks
icmp_slow, icmp_medium, icmp_rapid = ({} for i in range(3))

# icmp dist step 2
icmp_dist_slow, icmp_dist_medium, icmp_dist_rapid = ({} for i in range(3))

# icmp One-to-One dicts fro Slow, Medium and Rapid
icmp_onetoone_slow, icmp_onetoone_medium, icmp_onetoone_rapid = ({} for i in range(3))

# icmp one-to-many dicts for Slow, Medium and Rapid
icmp_onetomany_slow, icmp_onetomany_medium, icmp_onetomany_rapid = ({} for i in range(3))

# icmp many-to-one dicts for Slow, Medium and Rapid
icmp_manytoone_slow, icmp_manytoone_medium, icmp_manytoone_rapid = ({} for i in range(3))

# icmp many-to-many dicts for Slow, Medium and Rapid
icmp_manytomany_slow, icmp_manytomany_medium, icmp_manytomany_rapid = ({} for i in range(3))