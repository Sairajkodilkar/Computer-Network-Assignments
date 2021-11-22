#!/usr/bin/env python3

import socket
import sys
import struct
import os.path
from threading import Thread

def parseURL(url):
    startIndex = url.find('//')

    if(startIndex == -1):
        startIndex = -2

    startIndex += 2
    endIndex = url.find('/', startIndex)

    if(endIndex == -1):
        filePath = "/"
        endIndex = len(url)
    else:
        filePath =  url[endIndex:]

    hostName = url[startIndex:endIndex]

    return hostName, filePath

class DNS:
    
    SERVERIP = "8.8.8.8"
    SERVERPORT = 53
    
    def resolve(self, hostName):
        query = self._constructQuery(hostName)
        dnsSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytesSent = dnsSocket.sendto(query, (self.SERVERIP, self.SERVERPORT))
        if(bytesSent == 0):
            raise Exception("could not send message")
        response, address = dnsSocket.recvfrom(1024)
        dnsSocket.close()
        return self._decodeResponse(response)
    
    def _constructQuery(self, hostName):
        query = bytes.fromhex("1212 0100 0001 0000 0000 0000")

        for token in hostName.split("."):
            query += struct.pack("!b" + str(len(token)) + "s", len(token),
                    bytes(token, "utf-8"))

        query += bytes.fromhex("00 0001 0001")
        return query

    def _decodeResponse(self, dnsresponse):
        flag = int.from_bytes(dnsresponse[2:4], "big")

        if(flag & 0xf):
            raise Exception("cant resolve hostname")

        RDATA = dnsresponse[len(dnsresponse) - 4:]
        return socket.inet_ntoa(RDATA)

class HTTP:
    SERVERPORT = 80
    GETREQUEST =    "GET {} HTTP/1.1\r\n" + \
                    "Host: {}\r\n" + \
                    "Connection: {}\r\n" +  "\r\n"

    def sendRequest(self, socket, hostName, fileName):
        httpRequest = self._constructGetRequest(hostName, fileName)
        bytesSent = socket.send(httpRequest.encode())
        return bytesSent

    def recvResponse(self, socket):
        httpResponse = socket.recv(1024)
        httpMessage, entity = self._splitResponse(httpResponse)
        headersdict = self._parseHeader(httpMessage.decode())
        entitysize = int(headersdict['CONTENT-LENGTH'])
        while(len(entity) < entitysize):
            entity += socket.recv(1024)
        return headersdict, entity.decode(), entitysize

    def _constructGetRequest(self, hostName, fileName, connection="close"):
        return self.GETREQUEST.format(fileName, hostName, connection)

    def _splitResponse(self, httpRequest):
        s = httpRequest.split(bytes("\r\n\r\n", "utf-8"))
        return s[0], s[1]

    def _parseHeader(self, httpHeader):
        headerslist = httpHeader.split("\r\n")
        headersdict = {}
        headersdict["STATUS"] = headerslist[0][headerslist[0].find(" ") + 1:]
        for header in headerslist[1:]:
            colonIndex = header.find(":")
            headersdict[header[0:colonIndex].upper()] = header[colonIndex + 2:]

        return headersdict

def getUniqueFileName(filePath):
    fileName = os.path.basename(filePath)
    if(fileName == ''):
        fileName = "index.html"
    if(os.path.exists(fileName)):
        count = 1
        while(os.path.exists(fileName + "." + str(count))):
            count += 1
        fileName += "." + str(count) 

    return fileName

def wget(hostName, hostIP, filePath):
    http = HTTP()
    wgetSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wgetSocket.connect((hostIP, http.SERVERPORT))

    print("Connected to {}|{}|{}... ".format(hostName, hostIP, http.SERVERPORT))

    http.sendRequest(wgetSocket, hostName, filePath)

    print("HTTP request sent to {}|{}|{}, awaiting response..."
            .format(hostName, hostIP, http.SERVERPORT))

    headersdict, entity, entitysize = http.recvResponse(wgetSocket)
    status = headersdict["STATUS"]
    wgetSocket.close()

    print("Response recieved from {}|{}|{}, Size: {}, Status: {}"
            .format(hostName, hostIP, http.SERVERPORT, entitysize, status))

    if(status != "200 OK"):
        print("Aborting {}{}".format(hostName,filePath))
        return 

    fileName = getUniqueFileName(filePath)

    print("storing {}{} as {}".format(hostName, filePath, fileName))

    fstream = open(fileName, "w")
    fstream.write(entity)
    fstream.close()

if __name__ == "__main__":

    dns = DNS()
    hostNameIPDict = {}

    if(len(sys.argv) < 2):
        print("Usage: mywget <url>...")
        sys.exit()

    for i in range(1, len(sys.argv)):
        url = sys.argv[i]
        hostName, filePath = parseURL(url)
        hostIP = ''
        if(hostName in hostNameIPDict):
            hostIP = hostNameIPDict[hostName]
        else:
            hostIP = dns.resolve(hostName)
            hostNameIPDict[hostName] = hostIP

        print("Resolved " + hostName + " to " + hostIP)

        wgetThread = Thread(target=wget, args=(hostName, hostIP, filePath))
        wgetThread.start()

