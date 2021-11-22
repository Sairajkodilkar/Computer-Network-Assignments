#!/usr/bin/env python
from socket import *
from threading import Thread
from state import State
import signal
import sys
class Client:
    '''
    '''

    def __init__(self, user_name, server_address):
        self.clientSocket = socket(AF_INET, SOCK_STREAM)
        self.clientSocket.connect(server_address)
        self.clientName = user_name
        self.clientID = self.clientSocket.recv(1024).decode()
        self.clientSocket.send(self.clientName.encode())

    def startClient(self):
        self.sendThread = Thread(target=self.sendMessages)
        self.receiveThread = Thread(target=self.receiveMessages)
        self.clientState = State.Running
        self.sendThread.start()
        self.receiveThread.start()

    def sendMessages(self):
        while self.clientState == State.Running:
            message = input()
            message = self.clientID + " " + self.clientName + ": " + message
            self.clientSocket.send(message.encode())

    def receiveMessages(self):
        while self.clientState == State.Running:
            message = self.clientSocket.recv(1024).decode()
            receivedID, messageStart = self.tokanizeMessage(message)
            if(receivedID == -1):
                self.clientState = State.Stop
                print("server has stopped :(")
                print("You cannot communicate anymore")
            elif(receivedID != self.clientID):
                print(message[messageStart:])


    def tokanizeMessage(self, message):
        spaceIndex = message.index(' ')
        return message[0:spaceIndex], spaceIndex + 1



if __name__ == "__main__":
    if(len(sys.argv) != 3):
        print('Usage: client.py <port no> <username>')
        sys.exit(1)

    serverIP = '127.0.0.1'
    serverPort = int(sys.argv[1])
    userName = sys.argv[2]

    client = Client(userName, (serverIP, serverPort))
    client.startClient()




