from library import *
import struct
import random
import socket

class Server:

    def __init__(self, bindingAddress, probablity):
        self.rdt = RDT(1 - probablity)
        self.rdt.bind(bindingAddress)
        self.clients = {}

    def start(self):
        while True:
            data, address = self.rdt.recv(1024)
            packet = AppPacket.from_bytes(data)
            self.handlePacket(packet, address)

    def handlePacket(self, packet, address):
        if(packet.seqNo == 0):
            self.clients[address] = (int.from_bytes(packet.data, "big"), packet.connectionID)
        elif(packet.seqNo == 1):
            if(address not in self.clients):
                print("wrong sequence number from client")
                return
            else:
                numberOfNumbers = self.clients[address][0]
                numbers = struct.unpack("!" + str(numberOfNumbers) + "h", packet.data)
                sumOfNumbers = sum(numbers)
                data = struct.pack("!h", sumOfNumbers)
                packet = AppPacket(self.clients[address][1], 1, 0, data)
                self.rdt.send(packet.encode(), address)


server = Server(("", 8080), 1)
server.start()


        



