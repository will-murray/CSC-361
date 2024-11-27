import struct
import socket
import sys
from datetime import datetime, timedelta


reference_datetime = datetime(1970, 1, 1)

class IP_Datagram():
    
    def __init__(self,buffer,incl_len,ts_sec, ts_usec):
        self.timestamp = reference_datetime + timedelta(seconds=ts_sec,microseconds=ts_usec)
        self.ethernet_header = buffer[:14]
        self.header = IP_Header(buffer[14:34])

        raw_payload = buffer[14 + self.header.header_length:] #ethernet header length + IP header length
       
        if self.header.proto == 1: # ICMP
            self.payload = ICMP_Message(raw_payload)

        elif self.header.proto == 17: # UDP
            self.payload = UDP_Message(raw_payload)
        
        else: # proto == TCP
            self.payload = TCP_Message(raw_payload)
    




class IP_Header():
    def __init__(self, buffer):
        ip_fields = struct.unpack("!BBHHHBBH4s4s", buffer)
        self.id = ip_fields[3]
        self.ttl = ip_fields[5]
        self.proto = ip_fields[6]
        self.source = socket.inet_ntoa(ip_fields[8])
        self.dest = socket.inet_ntoa(ip_fields[9])
        self.flags_fragment_offset = ip_fields[4]
        self.frag_offset = self.flags_fragment_offset & 0x1FFF  # Lower 13 bits
        self.ihl = ip_fields[0] & 0x0F  # Extract the lower 4 bits from the first byte (IHL)
        self.header_length = self.ihl * 4  # Multiply by 4 to get the actual length in bytes



    

    def __str__(self):
        return f"id : {self.id} | proto : {self.proto}"

class ICMP_Message():
    def __init__(self,buffer):
        self.icmp_header = buffer[:8]
        self.icmp_fields = struct.unpack("!BBHHH", self.icmp_header) 
        self.icmp_type = self.icmp_fields[0]
        self.icmp_id = self.icmp_fields[2]
        self.OG_header = IP_Header(buffer[8:28])

class UDP_Message():

    def __init__(self,buffer):
        udp_header = buffer[:8]  # IP header is 20 bytes, UDP header is 8 bytes
        udp_fields = struct.unpack("!HHHH", udp_header)
        self.udp_src_port = udp_fields[0]
        self.udp_dest_port = udp_fields[1]

class TCP_Message():

    def __init__(self,buffer):
        self.src_port, self.dest_port, self.seq, self.ack, self.offset_reserved_flags, self.window_size = struct.unpack('!HHLLHH', buffer[:16])
        self.offset = (self.offset_reserved_flags >> 12) * 4 
        self.flags = self.offset_reserved_flags & 0x01FF  # Last 9 bits are the flags
        

def analyze_traceroute(file_path):
    # Open the PCAP file
    with open(file_path, "rb") as f:
        # Read and parse the PCAP global header (24 bytes)
        global_header = f.read(24)
        
        L = [] #set of datagrams
        # Iterate over the packet headers and data
        while True:
            # Read the next packet header (16 bytes)
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("IIII", packet_header)
            packet_data = f.read(incl_len)
            packet = IP_Datagram(packet_data,incl_len,ts_sec,ts_usec)
            L.append(packet)



            
    return L
            

# Example usage
L = analyze_traceroute(sys.argv[1])

for l in L:
    if l.header.proto == 1: #ICMP message
        pass






# Windows uses ICMP
# Linux/Unix uses UDP

# 1 -> ICMP
# 6 -> TCP
# 17 -> UDP
