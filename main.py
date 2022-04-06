import scapy.all as scapy


def scan(ip):
  #Discover network clients
  arp_request = scapy.ARP(pdst=ip)
  #Create broadcast message
  broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
  #Send broadcast msg to everyone
  arp_request_broadcast = broadcast/arp_request
  #Use sr (Send and Receive packets to test scanner)
  scapy.srp(arp_request_broadcast)
  #Store response value (packet answer and unanswered). Timeout = no response = terminate execution
  answered, unanswered = scapy.srp(arp_request_broadcast, timeout=1)
  print(answered)

scan("10.0.2.0/24")
