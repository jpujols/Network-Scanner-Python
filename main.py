import scapy.all as scapy

#Discover clients on network
def scan(ip):
  arp_request = scapy.ARP()
  arp_request.pdst=ip
  print(arp_request.summary())
  scapy.ls(scapy.ARP())
  
scan("192.168.1.0/24")