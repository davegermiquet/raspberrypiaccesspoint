#!/usr/bin/python
import ConfigParser
import netifaces
import threading
import time
from Queue import Empty
from multiprocessing import Process, Manager
# from scapy.all import *
from pyroute2 import IPDB
from scapy.all import Ether, IP, UDP, DHCP, BOOTP, get_if_raw_hwaddr, get_if_hwaddr, conf, sniff, sendp
from twisted.internet.selectreactor import SelectReactor
from wpa_supplicant.core import WpaSupplicantDriver


class PythonWifiScanner:
    wifiAccessPoints = []

    def change_ip(self, ipObject, netInterface):
        ipdb = IPDB()
        ips = ipdb.interfaces[self.get_interface(netInterface)]
        ipAddrs = ips.ipaddr.ipv4[0]
        ips.del_ip(ipAddrs['address'], ipAddrs['prefixlen'])
        ips.add_ip(ipObject['ipAddr'], 24)
        ipdb.commit()
        ipdb.routes.add(dst="default", gateway=ipObject['router'])
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

    def __init__(self, reactor):
        self._reactor = reactor
        threading.Thread(target=self._reactor.run, kwargs={'installSignalHandlers': 0}).start()
        time.sleep(0.1)  # let reactor start
        self.driver = WpaSupplicantDriver(reactor)
        self.supplicant = self.driver.connect()
        time.sleep(0.1)
        self.net_iface = netifaces.interfaces()

    def dhcp_print(self, pkt):
        self.q.put(str(pkt))

    def get_configured_networks(self, interfaceNumber):
        return self.supplicant.get_interface(self.net_iface[interfaceNumber].decode()).get_networks()

    def get_single_wpa_interface(self, interfaceNumber):
        return self.supplicant.get_interface(self.net_iface[interfaceNumber].decode())

    def get_interface(self, number):
        return str(self.net_iface[number].decode())

    def get_interfaces(self):
        return self.net_iface

    def select_network(self, network_path, interfaceNumber):
        print("Selecting network")
        print("Network path" + network_path)
        return self.supplicant.get_interface(self.net_iface[interfaceNumber].decode()).select_network(network_path)

    def add_network(self, network_cfg, interfaceNumber):
        return self.supplicant.get_interface(self.net_iface[interfaceNumber].decode()).add_network(network_cfg)

    def scan_interface_for_networks(self, interfaceNumber):
        interface = self.supplicant.get_interface(self.net_iface[interfaceNumber].decode())
        wifiNetworks = interface.scan(block=True)
        return wifiNetworks

    def get_dhcp_object(self, interfaceNumber):
        self.q = Manager().Queue()
        c = Process(target=self.callSniffer, args=(interfaceNumber,)).start()
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

    def callSniffer(self, interfaceNumber):
        inter = self.get_interface(interfaceNumber)
        conf.iface = inter
        print inter
        sniff(iface=inter, filter="udp", prn=self.dhcp_print, timeout=10)

    def callPacket(self, interfaceNumber):
        inter = self.get_interface(interfaceNumber)
        print inter
        fam, hw = get_if_raw_hwaddr(inter)
        macaddress = get_if_hwaddr(inter)
        conf.iface = inter
        ethernet = Ether(dst="ff:ff:ff:ff:ff:ff", src=macaddress, type=0x800)
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=hw, xid=0x10000000)
        dhcp = DHCP(options=[("message-type", "discover"), ("end")])
        packet = ethernet / ip / udp / bootp / dhcp
        sendp(packet, iface=inter)


# Start a simple Twisted SelectReactor
configParser = ConfigParser.RawConfigParser()
configParser.read(r'wificonfig.cfg')
sample_network_cfg = {}
sample_network_cfg['ssid'] = configParser.get('accesspoint', 'ssid')
sample_network_cfg['psk'] = configParser.get('accesspoint', 'psk')
print "Connecting to " + sample_network_cfg['ssid']
print "with password " + sample_network_cfg['psk']
reactor = SelectReactor()
dave = PythonWifiScanner(reactor)
configpath = dave.add_network(sample_network_cfg, 3)
dave.select_network(configpath.get_path(), 3)
time.sleep(1)
dhcpObject = dave.get_dhcp_object(3)
time.sleep(1)
for dhcpKey in dhcpObject.keys():
    print str(dhcpKey) + ":" + str(dhcpObject[dhcpKey])
dave.change_ip(dhcpObject, 3)
reactor.stop()
