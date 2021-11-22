#!/usr/bin/env python3
import struct
import socket
import random
from collections import deque
from threading import Thread
import sys
'''
NOTE: Connection is half duplex
'''

def get16BitCheckSum(data):
    '''For Now it is always zero'''
    #return checksum
    return int(0).to_bytes(2, 'big')

def validate16bitCheckSum(checksum, data):
    '''For now checksum is always valid'''
    return True

class Packet:
    #TODO modify the packet class to individually contain all the fields
    FIELD_LEN = 2
    IDENTITY_START = 0
    SEQ_NO_START = 2
    ACK_FLAG_START = 4
    DATA_LEN_START = 6
    CHECKSUM_START = 8
    DATA_START = 10
    def __init__(self):
        self.pkt = None

    def make_pkt(self, identity, seq_no, isack, checksum, data):
        '''
        Packet format
        +---------------+----------------+
        | IDENTITY      | SEQ NO.        | 
        +---------------+----------------+
        | ISACK         | DATA_LEN       | 
        +---------------+----------------+
        | CHECKSUM      |                |
        +---------------+                |
        //           DATA               //
        |                                |
        +--------------------------------+
        '''
        self.pkt = struct.pack("!4h", identity, seq_no, isack, len(data)) + checksum + data 

    def to_bytes(self):
        return self.pkt

    def from_bytes(self, pkt):
        self.pkt = pkt 
    
    def extract(self):
        len_data = int.from_bytes(self.pkt[6:8], 'big')
        return struct.unpack("!5h" + str(len_data) + "s", self.pkt)

    def isack(self):
        ack = self.pkt[self.ACK_FLAG_START: self.ACK_FLAG_START + self.FIELD_LEN]
        if(int.from_bytes(ack, 'big') & 0x1):
            return True

    def get_seq_no(self):
        seq_no = self.pkt[self.SEQ_NO_START:self.SEQ_NO_START + self.FIELD_LEN]
        return int.from_bytes(seq_no, 'big')

    def get_id(self):
        if(self.pkt is None):
            raise Exception("danger")
        identity = self.pkt[self.IDENTITY_START:self.IDENTITY_START + self.FIELD_LEN]
        return int.from_bytes(identity, 'big')

    def is_currupted(self):
        #implementation coming soon
        return False
    def get_data(self):
        data_end = self.DATA_START + int.from_bytes(self.pkt[self.DATA_LEN_START:self.DATA_LEN_START + self.FIELD_LEN], 'big')
        return self.pkt[self.DATA_START:self.DATA_START + data_end]


class UDT:

    def __init__(self, probability=1):
        self.probability = probability
        self.udt_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def sendto(self, data, address):
        if(self.droppacket()):
            return 0
        return self.udt_socket.sendto(data, address)

    def recvfrom(self, bufsize):
        return self.udt_socket.recvfrom(1024)

    def droppacket(self):
        set_boundries = self.probability * 100
        random_no = random.randint(1, 100)
        if(random_no <= set_boundries):
            return True
        return False
        
    def bind(self, address):
        self.udt_socket.bind(address)

    def settimeout(self, timeout):
        self.udt_socket.settimeout(timeout)

    def setblocking(self, flag):
        self.udt_socket.setblocking(flag)

    def getblocking(self):
        return self.udt_socket.getblocking()


class RDT:

    CHUNK_SIZE = 1 << 10

    WAIT_FOR_CALL = 0
    WAIT_FOR_ACK = 1
    SEND_PKT = 2

    MAX_TIMEOUT = 3

    INITIAL_TIME_OUT = 0.1

    def __init__(self, probability):
        self.udt = UDT(probability)
        self.transaction_id = random.randint(0, 1 << 16 - 1)
        self.npackets = 0

        self.timeout = self.INITIAL_TIME_OUT

        self.lock = False
        self.stop = False

        self.initsender()
        self.initrecvr()

        self.clientStates = {}

    def initsender(self):
        self.sender_state = self.WAIT_FOR_CALL
        self.sender_pkt = Packet()
        self.sender_seq_no = 0

    def initrecvr(self):
        self.recvr_seq_no = 0
        self.recvr_queue = deque()
        self.recvr_thread = Thread(target=self._recv, args=(self.CHUNK_SIZE,))
        self.recvr_thread.start()

    def send(self, data, address):
        #data must be in encoded format
        self.lock = True
        self.npackets += 1
        self.timeout = self.INITIAL_TIME_OUT
        while(True):
            if(self.sender_state == self.WAIT_FOR_CALL):
                checksum = get16BitCheckSum(data)
                self.sender_pkt.make_pkt(self.transaction_id, self.sender_seq_no, 0, checksum, data)
                self.sender_state = self.SEND_PKT

            elif(self.sender_state == self.SEND_PKT):
                self.udt.setblocking(True)
                byteCount = self.udt.sendto(self.sender_pkt.to_bytes(), address)
                if(byteCount <= 0):
                    print("Dropped Packet {}, ID: {}".format(self.npackets,
                        self.sender_pkt.get_id()))
                print("waiting for ack")
                self.sender_state = self.WAIT_FOR_ACK

            elif(self.sender_state == self.WAIT_FOR_ACK):
                reply_pkt = Packet()
                try:
                    self.udt.settimeout(self.timeout)
                    data, address = self.udt.recvfrom(self.CHUNK_SIZE)
                    reply_pkt.from_bytes(data)
                except socket.timeout:
                    print("Timeout: Packet {}, ID: {}".format(self.npackets,
                        self.sender_pkt.get_id()))

                    self.sender_state = self.SEND_PKT

                    print("Retransmistting Packet {}, ID: {}".format(self.npackets,
                        self.sender_pkt.get_id()))
                    continue
                else:
                    if(reply_pkt.isack()):
                        currupted = reply_pkt.is_currupted()
                        valid_ack = reply_pkt.get_seq_no() == self.sender_seq_no
                        valid_transaction = reply_pkt.get_id() == self.transaction_id

                        if(not currupted and valid_ack and valid_transaction):
                            print("Sucessfully transmitted Packet {}, ID: {}".format(
                                self.npackets, self.sender_pkt.get_id()))
                            self.sender_state = self.WAIT_FOR_CALL
                            self.sender_seq_no = (self.sender_seq_no + 1) % 2
                            self.timeout = 1
                            self.lock = False
                            return
                        elif(currupted):
                            print("Retransmistting Packet {}, ID: {}".format(
                                self.npackets, self.sender_pkt.get_id()))
                            self.sender_state = self.SEND_PKT
                        elif(not valid_ack or not valid_transaction):
                            self.sender_state = self.WAIT_FOR_ACK
                    else:
                        #the packet contains data 
                        self.recvr_queue.append(reply_pkt)
                        self.sender_state = self.WAIT_FOR_ACK

    def recv(self, buffersize):
        while(not self.recvr_queue):
            continue
        data = ''
        packet, address = self.recvr_queue.pop()

        return packet.get_data(), address

    def _recv(self, buffersize):
        pkt = Packet()
        ack = Packet()
        ack_data = ''.encode()
        while(not self.stop):
            if(self.lock):
                #lock aquire by the sender
                continue
            #non blocking enables us to check the lock 
            try:
                self.udt.settimeout(None)
                self.udt.setblocking(False) 
                data, address = self.udt.recvfrom(self.CHUNK_SIZE)
                pkt.from_bytes(data)

                currupted = pkt.is_currupted()
                valid_seq_no = pkt.get_seq_no() == self.recvr_seq_no
                isack = pkt.isack()

                unpack = pkt.extract()
                checksum = get16BitCheckSum(ack_data)

                if(not currupted and valid_seq_no and not isack):
                    ack.make_pkt(unpack[0], unpack[1], 1, checksum, ack_data)
                    byteCount = self.udt.sendto(ack.to_bytes(), address)
                    if(byteCount <= 0):
                        print("Ack Dropped for Seq No {}, ID: {}".format(
                            ack.get_seq_no(), ack.get_id()))
                    else:
                        print("Ack Sent for Seq No {}, ID: {}".format(
                            ack.get_seq_no(), ack.get_id()))
                    self.recvr_seq_no = (self.recvr_seq_no + 1) % 2
                    self.recvr_queue.append((pkt, address))

                elif(currupted):
                    #simply ignore the packet
                    continue

                elif(not valid_seq_no):
                    #send the seq no for the previous packet
                    ack.make_pkt(unpack[0], unpack[1], 1, checksum, ack_data)
                    byteCount = self.udt.sendto(ack.to_bytes(), address)
                    if(byteCount <= 0):
                        print("Ack Dropped for Seq No {}, ID: {}".format(
                            ack.get_seq_no(), ack.get_id()))
                    else:
                        print("Ack Sent for Seq No {}, ID: {}".format(
                            ack.get_seq_no(), ack.get_id()))

            except BlockingIOError:
                continue
            except socket.timeout:
                continue

    def close(self):
        self.stop = True
        self.recvr_thread.join()
        pass

    def estimate_timeout(self):
        return self.timeout * 2

    def bind(self, address):
        self.udt.bind(address)
        pass

class AppPacket:
    
    def __init__(self, connectionID, isResponse, seqNo, data):
        self.connectionID = connectionID
        self.isResponse = isResponse
        self.seqNo = seqNo
        self.data = data #must be in byte format

    def encode(self):
        return struct.pack("!4h", self.connectionID, self.isResponse,
                self.seqNo, len(self.data)) + self.data

    def from_bytes(bytePacket):
        connectionID = int.from_bytes(bytePacket[0:2], "big")
        isResponse = int.from_bytes(bytePacket[2:4], "big")
        seqNo = int.from_bytes(bytePacket[4:6], "big")
        size = int.from_bytes(bytePacket[6:8], "big")
        data = bytePacket[8:8 + size]

        return AppPacket(connectionID, isResponse, seqNo, data)

