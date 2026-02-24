#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IntField, ShortField, LongField, BitField, IP, UDP, TCP, Raw
from scapy.all import bind_layers

class cap(Packet):
    name = "cap"
    fields_desc = [ BitField("c", 0, 128),
                    BitField("tstamp", 0, 16),
                    BitField("pid", 0, 16),
                    BitField("type", 0, 4),
                    BitField("key_version", 0, 2),
                    BitField("padding", 0, 60)]

bind_layers(TCP, cap)

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "enp8s0f0np0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find veth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<2:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print(("sending on interface %s to %s" % (iface, str(addr))))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    # pkt = pkt /IP(dst=addr, flags='evil') / TCP(dport=1234, sport=random.randint(49152,65535)) / cap(c=1, tstamp=2,pid=3,type=0,key_version=0,padding=0) / sys.argv[2]
    pkt = pkt /IP(dst=addr, tos=2) / TCP(dport=50000, sport=1234) / sys.argv[2]
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
