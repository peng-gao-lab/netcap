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
import argparse as ap
import socket
from struct import pack
from scapy.all import *
from ctypes import *
import pyroute2
import tailer
from ctypes import Structure, c_uint32, c_ushort, c_ubyte
import struct

LOGS = {
    "/var/log/secure": re.compile(r"\bAccepted\b.*\bfrom\s+([0-9.]+)\s+port\s+(\d+)\b"),
    # Add more files + regex as needed
}

class Key(Structure):
    _fields_ = [
        ("ip", c_uint32),
        ("port", c_ushort), 
    ]

def pick_nic():
    names = [name for (_idx, name) in socket.if_nameindex()]
    if "enp0s3" in names:
        return "enp0s3"
    for n in names:
        if n.startswith("enp"):
            return n
    return names[0]

def ip_to_u32_be(ip_str):
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]

def set_tag(tagged_map, client_ip_str, client_port):
    if client_port <= 0 or client_port > 65535:
        return
    k = Key(ip=ip_to_u32_be(client_ip_str), port=client_port)
    tagged_map[k] = c_ubyte(0)

def follow_file(path, regex, tagged_map, stop_evt):
    while not stop_evt.is_set():
        try:
            with open(path, "r") as f:
                for line in tailer.follow(f):
                    if stop_evt.is_set():
                        break
                    m = regex.search(line)
                    if not m:
                        continue
                    ip = m.group(1)
                    port = int(m.group(2))
                    set_tag(tagged_map, ip, port)
        except FileNotFoundError:
            time.sleep(1)
        except Exception:
            time.sleep(0.5)

def monitor_auth_logs(tagged_map):
    stop_evt = threading.Event()
    threads = []
    for path, regex in LOGS.items():
        t = threading.Thread(target=follow_file, args=(path, regex, tagged_map, stop_evt))
        t.daemon = True
        t.start()
        threads.append(t)
        print("Monitoring {}".format(path))
    return stop_evt, threads

def main():
    b = BPF(src_file="server_ebpf.c")

    device = pick_nic()
    print("USING NIC {}".format(device))

    tagged = b["tagged_port"]

    f_egress = b.load_func("handle_egress", BPF.SCHED_CLS)
    ipr = pyroute2.IPRoute()
    eth = ipr.link_lookup(ifname=device)[0]

    try:
        ipr.tc("add", "clsact", eth)
    except Exception:
        pass

    ipr.tc("add-filter", "bpf", eth, ":1",
           fd=f_egress.fd, name=f_egress.name,
           parent="ffff:fff3",
           classid=1, direct_action=True)

    stop_evt, threads = monitor_auth_logs(tagged)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set()
        for t in threads:
            t.join(timeout=0.5)
        try:
            ipr.tc("del", "clsact", eth)
        except Exception:
            pass

if __name__ == "__main__":
    main()