import struct
import socket
import sys
from datetime import datetime, timedelta
from collections import defaultdict
import math

reference_datetime = datetime(1970, 1, 1)

proto_map = defaultdict(lambda: "Other")
proto_map[1] = "ICMP"
proto_map[6] = "TCP"
proto_map[17] = "UDP"



class IP_Datagram():
    
    def __init__(self,buffer,incl_len,ts_sec, ts_usec):
        self.time = (ts_sec,ts_usec)
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
        elif self.header.proto == 17:
            s = f" | identifier = {self.payload.identifier}"

        # return str(self.timestamp) + " | " + str(self.time) + " | " + self.header.__str__() + s
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

        self.identifier = udp_fields[0]

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
                break
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("IIII", packet_header)
            packet_data = f.read(incl_len)
            packet = IP_Datagram(packet_data,incl_len,ts_sec,ts_usec)
            L.append(packet)
            count += 1

    return L

def extract_og_datagram(L):
    L = sorted(L, key = lambda x: x.header.ttl)
    for l in L:
        if l.header.proto == 1:
            if l.payload.icmp_type == 8:
                return [l.header.source, l.header.dest, l.header.id]
        elif l.header.proto == 17:
            return [l.header.source,l.header.dest,l.header.id]    
    exit("No valid source ip detected: check get_src_ip()")
    
def analyze_og_datagram(L,id):
    """
    given the data and the id of the origonal datagram sent from the source
    return the number of fragments and the offset of the last fragment 
    """
    L = [l for l in L if l.header.id == id]
    L = sorted(L, key = lambda x: x.header.frag_offset)

    num_fragments = len(L)
    final_offset = L[len(L) - 1].header.frag_offset
    return [num_fragments,final_offset]

def computeRTTs(outbound,inbound,L):

    t1 = inbound.timestamp
    O = [l for l in L if l.header.id == outbound.header.id] #set of datagrams leaving the src that share an id with the given outbound datagram
    RTTs = [(inbound.header.source,outbound.header.ttl,t1 - l.timestamp) for l in O]


    return RTTs

def find_matching_packages(L, src_ip,verbose):
    """
    match outgoing packages with thier returning ICMP 11 packages, and collect the set of protocols found in the whole trace file
    each match is recorded as a 3-tuple : (ip of intermediate router, ttl, IP header id of origonal outgoing package)
    """
    RTTs = []
    matches=[]
    protos = []
    
    L = sorted(L, key= lambda x: x.header.ttl)
    for i in L:   
        protos.append(i.header.proto)
        if i.header.proto == 1: 
            if i.payload.icmp_type == 11: #ICMP timeout packet detected

                icmp_og_packet_type = i.payload.OG_header.proto
                for j in L:
                    
                    if icmp_og_packet_type == j.header.proto and j.header.source == src_ip :#and i.timestamp > j.timestamp:
                         if i.payload.identifier == j.payload.identifier:
                                if verbose:
                                    # print(f"{proto_map[icmp_og_packet_type]} (outbound): {j}") 
                                    # print(f"ICMP 11 (return): {i}")
                                    print(f"RTT: {i.timestamp - j.timestamp} | {i.payload.identifier} | ttl : {j.header.ttl}")
                                matches.append((i.header.source, j.header.ttl,j.header.id))
                                RTTs += computeRTTs(outbound = j,inbound = i, L = L)
    
    protos = set(protos)
    return [matches,protos,RTTs]

def analyze_traceroute(L, fname, verbose = False,r2 = False):
    """
    L is a list of IP_Datagrams
    """         
    src_ip,dest_ip,og_id = extract_og_datagram(L)
    print(f"The IP address of the source node: {src_ip}")
    print(f"The IP address of the destination node: {dest_ip}")
    print(f"The IP address of the intermediate nodes:")

    matches,protos, RTTs = find_matching_packages(L,src_ip,verbose) 
    

    routers = list(set([m[:2] for m in matches]))
    routers = sorted(routers, key= lambda x: x[1])


    for r in routers:
        hop_num, ip = r[1], r[0]
        print(f"\trouter {hop_num}: {ip}")
    

    print(f"\nThe values in the protocol field of IP headers:")
    for idx,p in enumerate(protos):
        val = proto_map[p]
        if val == "Other":
            val = p
        print(f"\t{idx}: {val}")

    num_frags,final_offset = analyze_og_datagram(L,og_id)
    print(f"\nThe number of fragments created from the original datagram is: {num_frags}")
    print(f"The offset of the last fragment is: {final_offset}\n")

    out = []

    ids = set( [r[0] for r in RTTs] )
    
    for id,ttl in routers:
        R = [r[2] for r in RTTs if r[0] == id ]
        total_time = sum(R, timedelta())
        average_timedelta = total_time / len(R)
        differences = [(r - average_timedelta).total_seconds() ** 2 for r in R]
        variance = sum(differences) / len(R)
        std_dev = timedelta(seconds=math.sqrt(variance))

        print(f"The avg RTT between {src_ip} and {id} is: {average_timedelta} ms, the s.d. is: {std_dev} ms")
        if r2:
            out.append((fname, ttl, average_timedelta))
    
    if r2:
         out_agg = []
         for fname,ttl in set([o[:2] for o in out]):
            times = [o[2] for o in out if o[1] == ttl]
            avg_time = sum([t.total_seconds() for t in times]) / len(times)
            out_agg.append((fname, ttl, avg_time))
         
         for o in sorted(out_agg,key = lambda x: x[1]):
             print(o)

            
if len(sys.argv) == 1:
    fname = "PcapTracesAssignment3/group1-trace1.pcap"
    print(f"input file not provided as command line argument, defaulting to {fname}")
else:
    fname = sys.argv[1]

# Example usage
L = parse_traceroute(fname)
routers = analyze_traceroute(L, fname,verbose= False, r2 = False)







# Windows uses ICMP
# Linux/Unix uses UDP

# 1 -> ICMP
# 6 -> TCP
# 17 -> UDP
