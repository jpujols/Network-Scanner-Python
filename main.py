import scapy.all as scapy
import pprint


def scan(ip):
  #Discover network clients
  arp_request = scapy.ARP(pdst=ip)
  #Create broadcast message
  broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
  #Send broadcast msg to everyone
  arp_request_broadcast = broadcast/arp_request
 
  #Store response value (packet answer and unanswered). Timeout = no response = terminate execution
  answered_list = scapy.srp(arp_request_broadcast, timeout=1)[0]

  #Iterate over answered packets and analyze data
  for element in answered_list:
    print(element)

scan("10.0.2.0/24")
