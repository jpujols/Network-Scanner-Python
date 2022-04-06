import scapy.all as scapy
import sr

def scan(ip):
  #Discover network clients
  arp_request = scapy.ARP(pdst=ip)
  arp_request.show()
  #Create broadcast message
  broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
  broadcast.show()
  #Send broadcast msg to everyone
  arp_request_broadcast = broadcast/arp_request
  arp_request_broadcast.show()
  

scan("10.0.2.0/24")
