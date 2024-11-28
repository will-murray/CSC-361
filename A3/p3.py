import struct
import socket
import sys
from datetime import datetime, timedelta
from collections import defaultdict

reference_datetime = datetime(1970, 1, 1)

proto_map = defaultdict(lambda: "Other")
proto_map[1] = "ICMP"
proto_map[6] = "TCP"
proto_map[17] = "UDP"



class IP_Datagram():
    
    def __init__(self,buffer,incl_len,ts_sec, ts_usec):
        self.timestamp = reference_datetime + timedelta(seconds=ts_sec,microseconds=ts_usec)
        self.ethernet_header = buffer[:14]
        self.header = IP_Header(buffer[14:34])
        raw_payload = buffer[14 + self.header.header_length:] #ethernet header length + IP header length
       
        if self.header.proto == 1: # ICMP
            self.payload :ICMP_Message = ICMP_Message(raw_payload)

        elif self.header.proto == 17: # UDP
            self.payload :UDP_Message = UDP_Message(raw_payload)
        
        else: # proto == TCP
            self.payload : TCP_Message = TCP_Message(raw_payload)

    def __str__(self):
        s = ""
        if self.header.proto == 1:
            s = f" | icmp type: {self.payload.icmp_type} | identifier = {self.payload.identifier}"

        return self.header.__str__() + s
    
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
        return f"{self.source} -> {self.dest} | {proto_map[self.proto]} | TTL : {self.ttl} | id = {self.id}| offset = {self.frag_offset}"

class ICMP_Message():
    def __init__(self,buffer):
        self.icmp_header = buffer[:8]
        self.icmp_fields = struct.unpack("!BBHHH", self.icmp_header) 
        self.icmp_type = self.icmp_fields[0]
        self.icmp_id = self.icmp_fields[2]
        self.OG_header = IP_Header(buffer[8:28])
        self.identifier = None

        """
        1. if the OG protocol was UDP and this ICMP message is time exceeded then this
        ICMP message can be identified through the UDP source port from the OG message 
        """
        if self.OG_header.proto == 17 and self.icmp_type == 11:
            self.identifier = struct.unpack("!HHHH", buffer[28:36])[0]   
        
        """
        if the og protocol is ICMP and this ICMP message is time exceeded then 
        this message can be identified through the sequence number from the OG message
        """
        if self.OG_header.proto == 1 and self.icmp_type == 11:
            self.identifier = struct.unpack("!BBHHH", buffer[28:36])[4]

        """
        if this package is an echo message then it can be identified
        """
        if self.icmp_type == 8: # echo message
            self.identifier = self.icmp_fields[4]
            
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
        
def parse_traceroute(file_path):
    """
    given the file path to a PCAP file, parse the file into a list of IP datagrams
        supports TCP, UDP and ICMP payloads
    """
    # Open the PCAP file
    with open(file_path, "rb") as f:
        # Read and parse the PCAP global header (24 bytes)
        globby = f.read(24)
        
        L = [] #set of datagrams
        # Iterate over the packet headers and data
        count = 0
        while True:
            # Read the next packet header (16 bytes)
            packet_header = f.read(16)
            if len(packet_header) < 16:
                print(f"parsed {count} packets")
                break
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("IIII", packet_header)
            packet_data = f.read(incl_len)
            packet = IP_Datagram(packet_data,incl_len,ts_sec,ts_usec)
            L.append(packet)
            count += 1

    return L

def get_src_ip(L):
    L = sorted(L, key = lambda x: x.header.ttl)
    return L[0].header.source

def analyze_traceroute(L, verbose = False):
    """
    L is a list of IP_Datagrams
    """         
    routers = []
    src_ip = get_src_ip(L)
    print(f"source ip = {src_ip}")

    for i in L:
        if i.header.proto == 1: 
            if i.payload.icmp_type == 11: #ICMP timeout packet detected

                icmp_og_packet_type = i.payload.OG_header.proto
                for j in L:

                    if icmp_og_packet_type == j.header.proto and j.header.source == src_ip:
                        if icmp_og_packet_type == 17: #origonal packet was UDP (linux implementation of traceroute)
                            #compare the UDP source ports
                            if i.payload.identifier == j.payload.udp_src_port:
                                if verbose:
                                    print(f"UDP (outbound): {j}") 
                                    print(f"ICMP 11 (inbound): {i}")
                                    print()
                                routers.append((i.header.source, j.header.ttl))


                        elif icmp_og_packet_type == 1: #origonal packer was ICMP echo message (windows implementation of traceroute)
                            if i.payload.identifier == j.payload.identifier:
                                if verbose:
                                    print(f"ICMP 8 (outbound): {j}")
                                    print(f"ICMP 11 (inbound): {i}")
                                    print()
                                routers.append((i.header.source, j.header.ttl))
    routers = list(set(routers))
    routers = sorted(routers, key= lambda x: x[1])
    return routers


if len(sys.argv) == 1:
    fname = "PcapTracesAssignment3/group1-trace1.pcap"
    print(f"input file not provided as command line argument, defaulting to {fname}")
else:
    fname = sys.argv[1]

# Example usage
L = parse_traceroute(fname)
routers = analyze_traceroute(L, verbose= True)

for r in routers:
    print(r)






# Windows uses ICMP
# Linux/Unix uses UDP

# 1 -> ICMP
# 6 -> TCP
# 17 -> UDP
