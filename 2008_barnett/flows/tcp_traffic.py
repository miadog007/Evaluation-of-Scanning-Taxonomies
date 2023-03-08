import dpkt
import socket



def tcp_speed(tcp_flows):
    '''
    Compare streams to find: 
        Ports + distrubution
    '''
    
    tcp_slow = {}
    tcp_medium = {}
    tcp_rapid = {}

    for flow, packets in tcp_flows.items():
        avg_time = packets[0]['avg_time_between_packets']
        if avg_time >= 5:
            tcp_slow[flow] = packets
        elif avg_time >= 1:
            tcp_medium[flow] = packets
        else:
            tcp_rapid[flow] = packets


def tcp_compare_src(speed_list):
    '''
    Function to compare ip src to put togheter
    '''
