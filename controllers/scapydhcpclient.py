#!/usr/bin/python

from scapy.all import Ether,IP,UDP,DHCP,BOOTP,get_if_raw_hwaddr,get_if_hwaddr,conf,sniff,sendp
#from scapy.all import *
from pyroute2 import IPDB
from Queue import Empty
from multiprocessing import Process, Queue, Manager
from wpa_supplicant.core import WpaSupplicantDriver
from twisted.internet.selectreactor import SelectReactor
import threading
import time
import errno
import sys
import types
import netifaces
import dbus
import json 
import re
    
class PythonDHCPScanner:
    
    wifiAccessPoints = []
    def change_ip(self,ipObject,netInterface):
        ipdb = IPDB()
        ips= ipdb.interfaces[self.get_interface(netInterface)]
        ipAddrs = ips.ipaddr.ipv4[0]
        ips.del_ip(ipAddrs['address'],ipAddrs['prefixlen'])
        ips.add_ip(ipObject['ipAddr'],24)
        ipdb.commit()
        ipdb.routes.add(dst="default",gateway=ipObject['router'])
        ipdb.commit()


    def queue_get_all(self):
        items = []
        maxItems = 50
        for numOfItemsRetrieved in range(0, maxItems):
           try:
               items.append(self.q.get_nowait())
           except Empty, e:
               break
        return items

    def __init__(self):
        self.net_iface = netifaces.interfaces()

    def dhcp_print(self,pkt):
        self.q.put(str(pkt))

    def get_interface(self,number):
        return str(self.net_iface[number].decode())
     
    def get_interfaces(self):
        return self.net_iface

    def get_dhcp_object(self,interfaceNumber):
        self.q = Manager().Queue()
        c = Process(target=self.callSniffer,args=(interfaceNumber,)).start()
        time.sleep(0.1)
        p = Process(target=self.callPacket(interfaceNumber)).start()
        time.sleep(5)
        if c is not None:
            c.join()
        dhcp = {}
        for strPkt in self.queue_get_all():
            try:
                pkt = Ether(strPkt)
                pkt.show()
                if pkt[Ether].dst == get_if_hwaddr(self.get_interface(interfaceNumber)):
                    if pkt[DHCP]:
                        if pkt.getlayer(DHCP).fields['options'][0][1] == 2:
                             if pkt[IP]:
                                 dhcp['ipAddr'] = pkt[IP].dst
                             for option in pkt.getlayer(DHCP).fields['options']:
                                 if option == 'end':
                                    break
                                 dhcp[option[0]] = option[1]
                             print dhcp['router']
                             print dhcp['subnet_mask']
                             break
            except:
                    continue
        return dhcp

    def callSniffer(self,interfaceNumber):
        inter = self.get_interface(interfaceNumber)
        conf.iface = inter
        print inter
        sniff(iface=inter,filter="udp",prn=self.dhcp_print, timeout=10)

    def callPacket(self,interfaceNumber):
        inter = self.get_interface(interfaceNumber) 
        print inter
        fam,hw = get_if_raw_hwaddr(inter)
        macaddress= get_if_hwaddr(inter)
        conf.iface = inter
        ethernet = Ether(dst="ff:ff:ff:ff:ff:ff",src=macaddress,type=0x800)
        ip = IP(src="0.0.0.0",dst="255.255.255.255")
        udp = UDP(sport=68,dport=67)
        bootp = BOOTP(chaddr =hw,xid=0x10000000)
        dhcp = DHCP(options=[("message-type","discover"),("end")])
        packet=ethernet/ip/udp/bootp/dhcp
        sendp(packet,iface=inter)

# get dhcp object

dave  = PythonDHCPScanner()
dhcpObject = dave.get_dhcp_object(3)
time.sleep(1)
for dhcpKey in dhcpObject.keys():
    print str(dhcpKey) + ":" + str(dhcpObject[dhcpKey])
time.sleep(1)
dave.change_ip(dhcpObject,3)

