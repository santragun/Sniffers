
from telnetlib import IP

from scapy.all import *
from scapy.layers.dns import DNS


def capturing_packet(captured_packet):
    src_ip=captured_packet[IP].src
    dst_ip=captured_packet[IP].dst
    if captured_packet.haslayer(DNS) and captured_packet.getlayer(DNS).qr==0:
       # print(str(src_ip)+" -> "+str(dst_ip)+" ( "+str(captured_packet.getlayer(DNS).qd.qname)+" ) ")
        print(captured_packet.summary())

        """DNS Query #5395: 192.168.0.2 -> 192.168.0.1: A www.google.com.
DNS Answer #5395: 192.168.0.1 -> 192.168.0.2: A www.google.com. 216.58.213.196"""

sniff(filter="port 53",prn=capturing_packet)