# Port
compare(barnett_oto_slow_icmp, barnett_oto_medium_icmp, barnett_oto_rapid_icmp, fukuda_icmp_port, 'icmp-port', 'one-to-one')
compare(barnett_otm_slow_icmp, barnett_otm_medium_icmp, barnett_otm_rapid_icmp, fukuda_icmp_port, 'icmp-port', 'one-to-many')
compare(barnett_mto_slow_icmp, barnett_mto_medium_icmp, barnett_mto_rapid_icmp, fukuda_icmp_port, 'icmp-port', 'many-to-one')
compare(barnett_mtm_slow_icmp, barnett_mtm_medium_icmp, barnett_mtm_rapid_icmp, fukuda_icmp_port, 'icmp-port', 'many-to-many')

# Network
compare(barnett_oto_slow_icmp, barnett_oto_medium_icmp, barnett_oto_rapid_icmp, fukuda_icmp_network, 'icmp-network', 'one-to-one')
compare(barnett_otm_slow_icmp, barnett_otm_medium_icmp, barnett_otm_rapid_icmp, fukuda_icmp_network, 'icmp-network', 'one-to-many')
compare(barnett_mto_slow_icmp, barnett_mto_medium_icmp, barnett_mto_rapid_icmp, fukuda_icmp_network, 'icmp-network', 'many-to-one')
compare(barnett_mtm_slow_icmp, barnett_mtm_medium_icmp, barnett_mtm_rapid_icmp, fukuda_icmp_network, 'icmp-network', 'many-to-many')

# One flow
compare(barnett_oto_slow_icmp, barnett_oto_medium_icmp, barnett_oto_rapid_icmp, fukuda_icmp_oflow, 'icmp-oflow', 'one-to-one')
compare(barnett_otm_slow_icmp, barnett_otm_medium_icmp, barnett_otm_rapid_icmp, fukuda_icmp_oflow, 'icmp-oflow', 'one-to-many')
compare(barnett_mto_slow_icmp, barnett_mto_medium_icmp, barnett_mto_rapid_icmp, fukuda_icmp_oflow, 'icmp-oflow', 'many-to-one')
compare(barnett_mtm_slow_icmp, barnett_mtm_medium_icmp, barnett_mtm_rapid_icmp, fukuda_icmp_oflow, 'icmp-oflow', 'many-to-many')

# Backscatter
compare(barnett_oto_slow_icmp, barnett_oto_medium_icmp, barnett_oto_rapid_icmp, fukuda_icmp_back, 'icmp-back', 'one-to-one')
compare(barnett_otm_slow_icmp, barnett_otm_medium_icmp, barnett_otm_rapid_icmp, fukuda_icmp_back, 'icmp-back', 'one-to-many')
compare(barnett_mto_slow_icmp, barnett_mto_medium_icmp, barnett_mto_rapid_icmp, fukuda_icmp_back, 'icmp-back', 'many-to-one')
compare(barnett_mtm_slow_icmp, barnett_mtm_medium_icmp, barnett_mtm_rapid_icmp, fukuda_icmp_back, 'icmp-back', 'many-to-many')

# Small
compare(barnett_oto_slow_icmp, barnett_oto_medium_icmp, barnett_oto_rapid_icmp, fukuda_icmp_small, 'icmp-small', 'one-to-one')
compare(barnett_otm_slow_icmp, barnett_otm_medium_icmp, barnett_otm_rapid_icmp, fukuda_icmp_small, 'icmp-small', 'one-to-many')
compare(barnett_mto_slow_icmp, barnett_mto_medium_icmp, barnett_mto_rapid_icmp, fukuda_icmp_small, 'icmp-small', 'many-to-one')
compare(barnett_mtm_slow_icmp, barnett_mtm_medium_icmp, barnett_mtm_rapid_icmp, fukuda_icmp_small, 'icmp-small', 'many-to-many')

# Other
compare(barnett_oto_slow_icmp, barnett_oto_medium_icmp, barnett_oto_rapid_icmp, fukuda_icmp_other, 'icmp-other', 'one-to-one')
compare(barnett_otm_slow_icmp, barnett_otm_medium_icmp, barnett_otm_rapid_icmp, fukuda_icmp_other, 'icmp-other', 'one-to-many')
compare(barnett_mto_slow_icmp, barnett_mto_medium_icmp, barnett_mto_rapid_icmp, fukuda_icmp_other, 'icmp-other', 'many-to-one')
compare(barnett_mtm_slow_icmp, barnett_mtm_medium_icmp, barnett_mtm_rapid_icmp, fukuda_icmp_other, 'icmp-other', 'many-to-many')