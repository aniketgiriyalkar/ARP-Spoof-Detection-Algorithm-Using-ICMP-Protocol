"""
File:           ARPattackDetection.py
Language:       python3
author:         Aniket Giriyalkar aag5405@rit.edu
                Ashish Paralkar amp3453@rit.edu
                Tanay Dusane tpd4203@rit.edu

Description:    In this program we implement the algorithm mentioned in the
                Paper.
"""

from scapy.all import *
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether

# query_DB_dict = {'00:50:56:f4:20:d9': '192.168.83.2',
#                  '00:50:56:c0:00:08': '192.168.83.1',
#                  '00:0c:29:b0:38:eb': '192.168.83.180',
#                  '00:0c:29:04:a3:f8': '192.168.83.182',
#                  '00:50:56:ef:97:b7': '192.168.83.254',
#                  '00:0c:29:f7:c1:3a': '192.168.83.183'}

query_DB_dict = {}

# Global Variables
checker_address_MAC = None
checker_address_IP = None


def QueryMappingDB(packet):
    """
    This function maintains a dictionary which stores all the unique <MAC, IP>
    mappings
    :param packet: packet the is sniffed
    :return: None
    """
    MACX = packet[ARP].hwsrc
    IPX = packet[ARP].psrc

    if packet[ARP].hwsrc in query_DB_dict.keys():
        pass
    else:
        if (packet[ARP].hwdst != "00:00:00:00:00:00" and
                    packet[Ether].dst != "ff:ff:ff:ff:ff:ff"):
            query_DB_dict[MACX] = IPX

    # print("me ithe yeun baghto")
    #
    # print(query_DB_dict)


def ARPattackDetection():
    """
    This function sniffs the information about ARP protocol.
    :return: None
    """
    sniff(filter="arp", prn=ARPanalysis,
          iface="VMware Virtual Ethernet Adapter for VMnet8")
    # interface can be changed according to whatever interface we are running
    #  the code on


def ARPanalysis(packet):
    """
    This function analyzes the ARP packets.
    :param packet: packet that is sniffed
    :return: None
    """
    # if(packet[ARP].hwdst != "00:00:00:00:00:00"
    # and packet[Ether].dst != "ff:ff:ff:ff:ff:ff"):

    QueryMappingDB(packet)

    if (packet[ARP].hwdst != packet[Ether].dst or packet[ARP].hwsrc
        != packet[Ether].src) and packet[
        ARP].hwdst != "00:00:00:00:00:00" and \
                    packet[Ether].dst != "ff:ff:ff:ff:ff:ff":
        print(packet[ARP].hwdst, packet[Ether].dst)
        print(packet[ARP].hwsrc, packet[Ether].src)

        print("Malformed packet found, notify the admin for MITM")
        return

    if packet[ARP].hwsrc in query_DB_dict.keys():

        if query_DB_dict[packet[ARP].hwsrc] == packet[ARP].psrc:
            print(query_DB_dict)
            print("Refreshing the data")
            # QueryMappingDB(packet)

        elif query_DB_dict[packet[ARP].hwsrc] != packet[ARP].psrc:
            print("Suspicious packet detected...."
                  "Initiating the ICMP response packet")

            # initiating response module
            print("Suspicious packet ---> ", packet[ARP].summary)
            # delete this thing

            SendICMPPacket(packet)


def SendICMPPacket(packet):
    """
    This function sends the ICMP packet to the suspicious host.
    :param packet: packet that is sniffed.
    :return:
    """

    test_packet = Ether(dst=packet[ARP].hwsrc) / \
                  IP(dst=packet[ARP].psrc, ttl=2) /\
                  ICMP(type="echo-request", code=0)

    global checker_address_IP
    checker_address_IP= packet[ARP].psrc             #Global variables to check


    global checker_address_MAC
    checker_address_MAC= packet[ARP].hwsrc           #Global variables to check

    respone, nonresponse = srploop(
        test_packet, iface="VMware Virtual Ethernet Adapter for VMnet8",
        timeout=10,count=10, prn=ICMPchecker)
    # print(respone,nonresponse)        #failed and non failed response

    if(nonresponse!=None):
        print("Arp poisoning detected.")

    """
    If ip forwaring is not enabled then we will not get the response
     from the packet.
    If ip forwarding is enabled then we will get a redirection packet
     or else we will get a different    
    """


def ICMPchecker(packet):
    """
    This function analyzes the reply of the ICMP response
    :param packet: packet that is sniffed.
    :return: None
    """

    # print(checker_address_MAC,checker_address_IP)

    if(packet[1][ICMP].type == 0):

        if(packet[1][IP].src != query_DB_dict[checker_address_MAC]):
            print("Suspicious host detected!")

        if(packet[1][Ether].src != checker_address_MAC):
            print("Suspicious host detected!")

        else:
            # updating the query_DB_dict
            query_DB_dict[packet[1][Ether].src] = packet[1][IP].src


def main():
    """
    The main function.
    :return: None
    """
    ARPattackDetection()

main()
