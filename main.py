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
  answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

  #Formats output and add 3 tabs between IP and MAC for user-friendly output
  print("IP\t\t\tMAC Address\n-----------------------")

  #Hold client IP and MAC in list
  clients_list = []
  
  #Iterate over answered packets and parse output with IP address and MAC address
  for element in answered_list:
    #Hold client IP and MAC in dictionary
    client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
    clients_list.append(client_dict)
    #format output to 2 columns
    print(element[1].psrc + "\t\t" + element[1].hwsrc)



scan("10.0.2.0/24")
