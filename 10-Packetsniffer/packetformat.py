from packet import *

UDP_PACKET_FORMAT = [
        PacketFormat.SHORT,     #Source port
        PacketFormat.SHORT,     #Destination port
        PacketFormat.SHORT,     #Data Length
        PacketFormat.SHORT,     #checksum
        PacketFormat.TILL_END   #Data
    ]

TCP_PACKET_FORMAT = [
        PacketFormat.SHORT,     #source port
        PacketFormat.SHORT,     #destination port
        PacketFormat.INTEGER,   #sequence number
        PacketFormat.INTEGER,   #ack number
        PacketFormat.SHORT,     #flag
        PacketFormat.SHORT,     #recv window
        PacketFormat.SHORT,     #internet checksum
        PacketFormat.SHORT,     #urgent data pointer
        PacketFormat.TILL_END   #data + options
    ]

IPV4_PACKET_FORMAT = [
        PacketFormat.BYTE,      #version + header length
        PacketFormat.BYTE,      #Type of service
        PacketFormat.SHORT,     #datagram length
        PacketFormat.SHORT,     #identifier
        PacketFormat.SHORT,     #flag + 13 bit fragmentation offset
        PacketFormat.BYTE,      #TTL
        PacketFormat.BYTE,      #upper layer protocol 17udp 06tcp
        PacketFormat.SHORT,     #header checksum
        4,                      #source IP address
        4,                      #destination IP address
        PacketFormat.TILL_END   #options + data
    ]

ETHERNET_PACKET_FORMAT = [
        6,                      #destination mac
        6,                      #source mac
        PacketFormat.SHORT,     #type
        PacketFormat.TILL_END   #data
    ]
