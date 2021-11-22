#Packet sniffer in python
#For Linux

import socket

#create an INET, raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.ntohs(0x0003))

# receive a packet
print(s.recvfrom(65565))
