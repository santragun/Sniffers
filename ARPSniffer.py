from scapy.all import *
from scapy.layers.inet import IP


def capturing_packet(captured_packet):
    src_ip = captured_packet[IP].src
    dst_ip = captured_packet[IP].dst
    dst_mac=captured_packet.dst
    print("Request: "+src_ip+" is requesting about "+dst_ip)
    print("Response : "+dst_mac+" has address "+dst_ip)

sniff(filter="ip",prn=capturing_packet)
