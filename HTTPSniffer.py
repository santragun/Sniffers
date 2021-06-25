from scapy.all import *

def http_header(packet):
    packet_str=str(packet)
    if packet_str.find('GET'):
        print(packet.summary())
    if(packet_str.find('POST')):
        print(packet.summary())
sniff(filter="tcp port 80",prn=http_header)