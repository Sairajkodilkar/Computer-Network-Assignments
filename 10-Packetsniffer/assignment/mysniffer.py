import sys
import string
import socket
import struct

class PacketFormat:

    BYTE            = 'B'
    SHORT           = 'H'
    INTEGER         = 'I'
    LONG_LONG       = 'Q'
    STRING          = 's'
    TILL_END        = -1
    BYTES_SIZE_TYPE = int

    BYTE_SIZE       = 1
    SHORT_SIZE      = 2
    INTEGER_SIZE    = 4
    LONG_LONG_SIZE  = 8

    def __contains__(self, format_specifier):
        return (format_specifier in (self.SHORT, self.INTEGER, self.LONG_LONG,
            self.BYTE, self.TILL_END, self.STRING) 
                or isinstance(format_specifier, int))


NETWORK_ENDIANESS = "big"

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
class PacketStructureError(Exception):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

def decode_pkt(packet, packet_format):
    if(not isinstance(packet, bytes)):
        raise PacketStructureError("Wrong Packet structure, expected bytes")

    packet_values = list()
    offset = 0
    #TODO: change key, value names to the sensible names
    counter = 0
    for value in packet_format:
        if(offset >= len(packet)):
            break

        elif(value not in PacketFormat()):
            raise PacketStructureError("Invalid format specifier")

        elif(isinstance(value, PacketFormat.BYTES_SIZE_TYPE)):
            if(value == PacketFormat.TILL_END):
                packet_values.append(packet[offset : ])
                offset = len(packet)
            else:
                packet_values.append(packet[offset : offset + value])
                offset += value

        elif(value == PacketFormat.STRING):
            string_len = packet_values[-1]
            packet_values.append(packet[offset : offset + string_len])
            offset += string_len

        elif(value == PacketFormat.BYTE):
            decode_value = struct.unpack("!" + value, 
                                        packet[
                                            offset :
                                            offset + PacketFormat.BYTE_SIZE
                                            ])
            packet_values.append(*decode_value)
            offset += PacketFormat.BYTE_SIZE

        elif(value == PacketFormat.SHORT):
            decoded_value = struct.unpack("!" + value, 
                                        packet[
                                            offset : 
                                            offset + PacketFormat.SHORT_SIZE
                                            ])
            packet_values.append(*decoded_value)
            offset += PacketFormat.SHORT_SIZE

        elif(value == PacketFormat.INTEGER):
            decoded_value = struct.unpack("!" + value, 
                                        packet[
                                            offset : 
                                            offset + PacketFormat.INTEGER_SIZE
                                            ])
            packet_values.append(*decoded_value)
            offset += PacketFormat.INTEGER_SIZE

        elif(value == PacketFormat.LONG_LONG):
            decoded_value = struct.unpack("!" + value, 
                                        packet[
                                            offset : 
                                            offset + PacketFormat.LONG_LONG_SIZE
                                            ])
            packet_values.append(*decoded_value)
            offset += PacketFormat.LONG_LONG_SIZE
        else:
            PacketStructureError("Invalid packet error")

    return tuple(packet_values)

def unpacketize_udp_packet(packet):
    return decode_pkt(packet, UDP_PACKET_FORMAT)

def unpacketize_tcp_packet(packet):
    return decode_pkt(packet, TCP_PACKET_FORMAT)

def unpacketize_ipv4_packet(packet):
    return decode_pkt(packet, IPV4_PACKET_FORMAT)

def unpacketize_ethernet_packet(packet):
    return decode_pkt(packet, ETHERNET_PACKET_FORMAT)

protocol_type = {
        "tcp":socket.IPPROTO_TCP,
        "udp":socket.IPPROTO_UDP,
        "ipv4":0x0008
    }

ethernet_header_names = [
        "Destination MAC:",
        "Source MAC:",
        "Type:"
    ]

ipv4_header_names = [ "Version",
        "Header length:",
        "Type of service:",
        "Datagram length:",
        "Identifier:",
        "Flag:",
        "Fragmenation:",
        "TTL:",
        "Protocol:",
        "Header checksum:",
        "Source address:",
        "Destination address:",
        "Options:"
    ]

tcp_header_name = [
        "Source port:",
        "Destination port:",
        "Seq No:",
        "Ack No:",
        "Header len:",
        "Flag:",
        "Window:",
        "Internet checksum:",
        "Urgent data pointer:",
        "Options:",
        "Data:"
    ]

udp_header_name = [
        "Source port:",
        "Destination port:",
        "Data length:",
        "Checksum:",
        "Data:"
    ]

ip_header_len = 20
tcp_header_len = 20

def eth_addr(a):
    b = ''
    for i in range(0,5):
        b += "{}:".format(a[i:i+1].hex())
    b += "{}".format(a[5:6].hex())
    return b

def print_headers(ethernet_header, ip_header, transport_header):
    print("ETHERNET HEADER")
    print("\t" + ethernet_header_names[0], eth_addr(ethernet_header[0]))
    print("\t" + ethernet_header_names[1], eth_addr(ethernet_header[1]))
    print("\t" + ethernet_header_names[2], ethernet_header[2])

    print("IPV4 HEADER")
    for i in range(0, 5):
        print("\t" + ipv4_header_names[i], ip_header[i])
    print("\t" + ipv4_header_names[5], hex(ip_header[5]))
    for i in range(6, 9):
        print("\t" + ipv4_header_names[i], ip_header[i])
    print("\t" + ipv4_header_names[9], hex(ip_header[9]))
    print("\t" + ipv4_header_names[10], socket.inet_ntoa(ip_header[10]))
    print("\t" + ipv4_header_names[11], socket.inet_ntoa(ip_header[11]))
    print("\t" + ipv4_header_names[12], ip_header[12].hex())

    if(ip_header[8] == protocol_type["tcp"]):
        print("TCP HEADER")
        for i in range(0, 5):
            print("\t" + tcp_header_name[i], transport_header[i])
        print("\t" + tcp_header_name[6], hex(transport_header[6]))
        print("\t" + tcp_header_name[7], transport_header[7])
        print("\t" + tcp_header_name[8], hex(transport_header[8]))
        print("\t" + tcp_header_name[9], transport_header[9].hex())

    else:
        print("UDP HEADER")
        for i in range(0, 3):
            print("\t" + tcp_header_name[i], transport_header[i])
        print("\t" + tcp_header_name[3], hex(transport_header[3]))

printable_bytes = string.printable.encode()

def print_hex(data_slice):
    i = 0
    for i in range(len(data_slice)):
        print(data_slice[i:i+1].hex(), end = " ")

def print_ascii(data_slice):
    i = 0
    for i in range(len(data_slice)):
        byte = data_slice[i:i+1]
        if(byte in printable_bytes):
            print(repr(byte)[2:-1], end= " ")
        else:
            print('.',end=" ")

def print_data(data):
    start = 0
    while(start < len(data)):
        length = min(len(data[start:]), 10)
        data_slice = data[start:start + length]
        print_hex(data_slice)
        print(" " * (10 - length) * 3, end='')
        print("\t", end='')
        print_ascii(data_slice)
        start += length
        print()

protocol_port = {
        "http":80,
        "ftp" :21,
        "telnet":23
    }

def sniff(destination_address, protocol_name):

    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                            socket.ntohs(0x0003))

    packet_no = 0
    while(True):
        packet = raw_socket.recvfrom(1<<17)[0]

        ethernet_header = unpacketize_ethernet_packet(packet)

        if(ethernet_header[2] != 0x0800): 
            continue

        ip_header = unpacketize_ipv4_packet(ethernet_header[-1])

        version_header = ip_header[0]
        version = (version_header & 0xf0) >> 4
        header_len = (version_header & 0x0f) * 4

        flag_fragmentation = ip_header[4]
        flag = (flag_fragmentation & 0xe000) >> (4 * 3 + 1)
        fragmentation = flag_fragmentation & 0x1fff

        options_data = ip_header[-1]
        options = options_data[:header_len - ip_header_len]
        data = options_data[header_len - ip_header_len:]

        ip_header = (version, header_len) + ip_header[1:4] + (flag,
            fragmentation) + ip_header[5:10] + (options, data)

        if((protocol_name 
                and (protocol_name == "tcp" or protocol_name == "udp") 
                and protocol_type[protocol_name] != ip_header[8])
            or (destination_address[0] 
                and destination_address[0] != socket.inet_ntoa(ip_header[11]))):
                continue

        transport_header = None

        if(ip_header[8] == protocol_type["tcp"]):
            transport_header = unpacketize_tcp_packet(ip_header[-1])
            header_len_flag = transport_header[4]
            header_len = ((header_len_flag & 0xf000) >> (8 * 2 - 4)) * 4
            flag = (header_len_flag & 0x003f)

            if(len(transport_header) < 9):
                transport_header += (b'',)

            if(header_len > tcp_header_len):
                options = transport_header[-1][:header_len - tcp_header_len]
            else:
                options = b''

            data = transport_header[-1][header_len - tcp_header_len:]

            transport_header = (transport_header[0:4] + (header_len, flag) 
                                + transport_header[5:8] + (options, data))
        else:
            transport_header = unpacketize_udp_packet(ip_header[-1])
        
        if(destination_address[1]
            and transport_header[1] != destination_address[1]):
            continue

        if(protocol_name and protocol_name != "udp" and protocol_name != "tcp"
                and (transport_header[1] != protocol_port[protocol_name])):
            continue

        print("======Packet {}======".format(packet_no))
        print_headers(ethernet_header, ip_header, transport_header)
        print("Data") 
        print_data(transport_header[-1])
        print("=====================")
        packet_no += 1


def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

if __name__ == "__main__":
    destination_ip = None
    destination_port = None
    protocol_name = None

    for arg in sys.argv[1:]:
        if(arg.isdigit()):
            destination_port = int(arg)
        elif(validate_ip(arg)):
            destination_ip = arg
        elif(arg in protocol_port.keys()):
            protocol_name = arg
        else:
            print("invalid argument")
            print("Usage: mysniffer.py [destination_ip] [destination_port] [protocol_name]")
            sys.exit(0)

    sniff((destination_ip, destination_port), protocol_name)
