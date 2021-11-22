#!/usr/bin/env python

from socket import *
from threading import Thread
from collections import deque
from state import State
import sys


class Server:

    def __init__(self, address, backlog=10):

        self.serverSocket = socket(AF_INET, SOCK_STREAM)
        self.serverSocket.bind(address)
        self.serverSocket.listen(backlog)

        self._serverState = State.Running

        self.clientCount = 0

        self.messageQueue = deque()
        self.clientSocketList = []

        self.broadcastThread = Thread(target=self._broadcastMessages)
        self.broadcastThread.start()

    def acceptRequests(self):
        while self.serverState == State.Running:
            connectionSocket, clientAddr = self.serverSocket.accept()
            print("Connected To: ", clientAddr)

            self.clientSocketList.append(connectionSocket)
            clientID = self.assignID(connectionSocket)
            userName = connectionSocket.recv(1024)
            alertMessage = str(clientID) + " " + userName.decode() + " has joined the chat"
            self.messageQueue.append(alertMessage.encode())

            connectionThread = Thread(target=self.receiveMessages, args=(connectionSocket,))
            connectionThread.start()

    def receiveMessages(self, connectionSocket):
        while self._serverState == State.Running:
            message = connectionSocket.recv(1024)
            self.messageQueue.append(message)

    def assignID(self, connectionSocket):
        self.clientCount += 1
        connectionSocket.send(str(self.clientCount).encode())
        return self.clientCount

    def _broadcastMessages(self):
        print("Broadcast thread started")
        while self._serverState == State.Running:
            if(self.messageQueue):
                message = self.messageQueue.popleft()
                self.sendAll(message)

    def sendAll(self, message):
        for clientSocket in self.clientSocketList:
            clientSocket.send(message)

    def closeAllConnections(self):
        for clientSocket in self.clientSocketList:
            clientSocket.close()

    @property
    def serverState(self):
        return self._serverState

    @serverState.setter
    def serverState(self, state):
        self._serverState = state



if __name__ == "__main__":

    global server
    if(len(sys.argv) != 2):
        print('Usage: server.py <port no>')
        sys.exit(1)

    serverIP = ''
    serverPort = int(sys.argv[1])
    server = Server((serverIP, serverPort))
    server.acceptRequests()

