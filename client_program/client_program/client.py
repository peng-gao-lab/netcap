#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports

from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import ArgString, printb
import bcc.utils as utils
import argparse
import re
import time
import pwd
from collections import defaultdict
from time import strftime
import sqlite3
import argparse as ap
import socket
from struct import pack
from scapy.all import *
from ctypes import *
import pyroute2

TAGGED_TERMINAL = 139099

def pick_nic():
    names = [name for (_idx, name) in socket.if_nameindex()]
    if "enp0s3" in names:
        return "enp0s3"
    for n in names:
        if n.startswith("enp"):
            return n
    return names[0]

# initialize BPF
b = BPF(src_file="host_agent_ebpf.c")
# b = BPF(src_file="host_agent_ebpf-same-packet.c")

b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_v4_connect_entry")

# Mellanox nic definitions
device = pick_nic()
print("USING NIC {}".format(device))


fn = b.load_func("handle_ingress", BPF.XDP)
b.attach_xdp(device, fn, 0)
f_egress = b.load_func("handle_egress", BPF.SCHED_CLS)
ipr = pyroute2.IPRoute()
eth = ipr.link_lookup(ifname=device)[0]
ipr.tc("add", "clsact", eth)
ipr.tc("add-filter", "bpf", eth, ":1", fd=f_egress.fd, name=f_egress.name,
           parent="ffff:fff3", classid=1, direct_action=True)

while 1:
    try:
        b.trace_print()
        # b.perf_buffer_poll()
    except KeyboardInterrupt:
        conn.close()
        b.remove_xdp(device, 0)   
        exit()
