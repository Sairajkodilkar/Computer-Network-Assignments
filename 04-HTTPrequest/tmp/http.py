#!/usr/bin/env python

'''
Observations:
    wget uses the non persistent HTTP 
'''
from socket import *

hostName = "info.cern.ch"

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((hostName, 80))
clientSocket.send("GET / HTTP/1.1\r\nHOST: info.cern.ch\r\n\r\n".encode())
msg = clientSocket.recv(1024)
print(msg.decode())


