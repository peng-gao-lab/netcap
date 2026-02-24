#!/usr/bin/env python3
import ipaddress
import sys
import os
from time import sleep
import random
sys.path.append(os.path.expandvars('$SDE/install/lib/python3.6/site-packages/tofino/'))
from bfrt_grpc import client
import grpc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import bfrt_grpc.client as gc

RECIRCULATION_PORT = 68
#Connect to BF Runtime Server 
interface = gc.ClientInterface(grpc_addr="localhost:50052", client_id=0,device_id=0) 
print('Connected to BF Runtime Server') 
# Get the information about the running program on the bfrt server. 
bfrt_info = interface.bfrt_info_get() 
print('The target runs program ', bfrt_info.p4_name_get()) 
# Establish that you are working with this program 
interface.bind_pipeline_config(bfrt_info.p4_name_get()) 
####### You can now use BFRT CLIENT #######
target = gc.Target(device_id=0, pipe_id=0xffff)

######### Get tables
forward_table = bfrt_info.table_get("table_forward")

# =========================================================

def addService(forward_table, dst_ip_addr, dst_port):
  key = forward_table.make_key([gc.KeyTuple('hdr.ipv4.dst_addr',dst_ip_addr), gc.KeyTuple('ig_md.do_fwd',1)])
  data = forward_table.make_data([gc.DataTuple('dst_port', dst_port)], 'SwitchIngress.route')
  forward_table.entry_add(target, [key], [data])


addService(forward_table, 0x0a000002, 61)
addService(forward_table, 0x0a000001, 60)

while True:
    try:
        # msg = interface.digest_get(timeout=0.1)
        # sleep(3)
        sleep(3000000)
    except:
        print("error")
        pass