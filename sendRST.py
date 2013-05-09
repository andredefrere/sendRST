#!/usr/bin/python
from scapy import *
from pymongo import MongoClient
import random
import time

def sendRST(p):
    flags = p.sprintf("%TCP.flags%")
    if flags != "S":
        ip = p[IP]      # Received IP Packet
        tcp = p[TCP]    # Received TCP Segment
        if ip.len   <= 40:
            return
        i = IP()        # Outgoing IP Packet
        i.dst = ip.dst
        i.src = ip.src
        t = TCP()       # Outgoing TCP Segment
        t.flags = "R"
        t.dport = tcp.dport
        t.sport = tcp.sport
        t.seq = tcp.seq
        new_ack = tcp.seq + 1
        print "RST sent to ",i.dst,":",t.dport
        send(i/t)

def sendFIN(p):
    flags = p.sprintf("%TCP.flags%")
    if flags != "S":
        ip = p[IP]      # Received IP Packet
        tcp = p[TCP]    # Received TCP Segment
        if ip.len   <= 40:
            return
        i = IP()        # Outgoing IP Packet
        i.dst = ip.dst
        i.src = ip.src
        t = TCP()       # Outgoing TCP Segment
        t.flags = "F"
        t.dport = tcp.dport
        t.sport = tcp.sport
        t.seq = tcp.seq
        new_ack = tcp.seq + 1
        print "FIN sent to ",i.dst,":",t.dport
        send(i/t)

def killOpsConns(t):
    connection = MongoClient()
    db = connection['admin']
    for x in range(0,t):
        # could do .find_one({"$all":"true"}) for db.currentOp(true) but unexpected things could result.
        for op in db['$cmd.sys.inprog'].find_one()['inprog']:
            for client in op:
                if client == 'client' and op["client"] != "0.0.0.0:0": 
                    ip = op["client"].split(":")
                    print "sniffing for packets on " + op["client"]
                    PKT = sniff(filter = "tcp and host "+ip[0], count=1, prn=sendRST)
        time.sleep(1)

killOpsConns(60)

exit()