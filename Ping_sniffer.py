from telnetlib import IP

from scapy.all import *

def capturing_packet(captured_packet):
    src_ip=+captured_packet[IP].src
    dst_ip=captured_packet[IP].dst
    print("\t source ip "+src_ip)
    print("\t destination ip "+dst_ip)

sniff(filter="icmp",prn=capturing_packet)


"""
echo-request (#42015): 192.168.0.1 -> 8.8.8.8
echo-reply (#42015): 8.8.8.8 -> 192.168.0.1
echo-request (#42015): 192.168.0.1 -> 192.168.0.2
echo-reply (#42015): 192.168.0.2 -> 192.168.0.1"""