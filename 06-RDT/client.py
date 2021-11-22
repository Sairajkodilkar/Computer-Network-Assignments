from library import *
import struct
import random
import socket


class Client:

    def __init__(self, address, probablity):
        self.connection_id = random.randint(1, 1 << 16 - 1)
        self.address = address
        self.rdt = RDT(1 - probablity)

    def start(self):
        n = random.randint(1, 10)
        data = struct.pack("!h", n) 
        packet = AppPacket(self.connection_id, 0, 0, data)
        try:
            self.rdt.send(packet.encode(), self.address)
        except socket.timeout:
            print("Server may be offline")
            sys.exit(0)

        randomList = self.genrateRandomList(n)
        randomSum = sum(randomList)
        randomNumbers = struct.pack("!" + str(n) + "h", *randomList)
        packet = AppPacket(self.connection_id, 0, 1, randomNumbers)
        try:
            self.rdt.send(packet.encode(), self.address)
        except socket.timeout:
            print("Server may be offline")
            sys.exit(0)

        data, address= self.rdt.recv(1024)
        packet = AppPacket.from_bytes(data)
        if(packet.connectionID != self.connection_id or packet.isResponse != 1):
            print("Server sent wrong reply")
            sys.exit(0)

        sumOfNumbers = int.from_bytes(packet.data, "big")
        if(randomSum == sumOfNumbers):
            print("Server sent Correct sum")
        else:
            print("Server Sent Incorrect sum")
        return

    def genrateRandomList(self, n):
        randomList = []
        for i in range(n):
            randomNumber = random.randint(1, 50)
            randomList.append(randomNumber)
        return randomList


c = Client(("localhost", 8080), 1)
c.start()


