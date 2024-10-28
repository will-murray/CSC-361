import struct
from datetime import datetime, timedelta



def glob_header(buff):

    arr = struct.unpack("IIIIII", buff)
    

def mac_addr(address_bytes):
    """Convert a MAC address from bytes to human-readable form."""
    return ':'.join(map('{:02x}'.format, address_bytes))

def ip_addr(address_bytes):
    """Convert an IP address from bytes to human-readable form."""
    return '.'.join(map(str, address_bytes))

def parse_ipv4_header(data):
    """Extract and return the total length, header length, source and destination IP using struct.unpack."""
    # Unpack the first 20 bytes of the IPv4 header
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4  # IHL is the last 4 bits
    total_length, src_ip, dest_ip = struct.unpack('!2xH8x4s4s', data[:20])

    return total_length, header_length, ip_addr(src_ip), ip_addr(dest_ip)

def parse_tcp_header(data):
    """Parse the TCP header and extract ports, sequence numbers, flags, and TCP header length."""
    src_port, dest_port, seq, ack, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4  # Data offset in the first 4 bits
    flags = offset_reserved_flags & 0x01FF  # Last 9 bits are the flags
    return src_port, dest_port, seq, ack, flags, offset, data[offset:]


def parse_flags(flags):
    flags = bin(flags)
    # Define the flags with their corresponding bit positions
    D = {
        0: "FIN",
        1: "SYN",
        2: "RST",
        3: "PSH",
        4: "ACK",
        5: "URG"
    }
    F = []
    for idx, bit in enumerate(reversed(flags[2:])):
        if int(bit):
            F.append(D[idx])


    return F

def parse_cap_file(file_path):
    L = []
    reference_datetime = datetime(1970, 1, 1)

    with open(file_path, 'rb') as f:
        # Skip the global header (24 bytes)
        glob = f.read(24)
        glob_header(glob)
        while True:
            # Read the packet header (16 bytes)
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break  # End of file

            #unpack the packet header
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', packet_header)
            packet_data = f.read(incl_len)
            
            #skip the Ethernet Header (first 14 bytes)
            payload = packet_data[14:]

            #get the ip header length, ip total length and the source/destination IP addresses 
            ip_total_length, ip_header_length, src_ip, dest_ip =  parse_ipv4_header(payload)

            payload = payload[ip_header_length:]

            src_port, dest_port, seq, ack, flags, tcp_header_length, payload = parse_tcp_header(payload)
            flags = parse_flags(flags)

            LENGTH = ip_total_length - ip_header_length - tcp_header_length
            time_delta = reference_datetime + timedelta(seconds=ts_sec, microseconds=ts_usec)

            L.append(tuple([src_ip, src_port, dest_ip, dest_port, seq, ack, flags, time_delta,LENGTH, incl_len]))
    
    
        
    return L

def unique_conns(data):
    """
    return all unique 4-tuples (src ip, src port, dest ip, dest port)
    up to transposition of source and destination
    """
    conns = []
    for i in data:
        a = i[:4] in conns
        b = (i[2],i[3],i[0],i[1]) in conns
        if not (a or b):
            conns.append(i[:4])
    return conns

def get_packets_by_id(id,data):
    D =  [i for i in data if id == i[:4] or id == (i[2],i[3],i[0],i[1])]
    D =  sorted(D, key=lambda x: x[7])
    return D

class Connection:
    def __init__(self,idx,connection_ids,data):
        self.ID = connection_ids[idx][:4]

        self.ip_a = self.ID[0]
        self.ip_b = self.ID[2]

        self.port_a = self.ID[1]
        self.port_b = self.ID[3]

        self.D =  [i for i in data if self.ID == i[:4] or self.ID == (i[2],i[3],i[0],i[1])]
        self.D =  sorted(self.D, key=lambda x: x[7])
        self.abs_start_time = data[0][7]

        

        self.idx = idx

    def __str__(self):
        s = ""
        for msg in self.D:
            s += str(msg) + '\n'
        return s
    
    def is_complete(self):
        """
        complete TCP connections for which we see at least one SYN and at least one FIN
        """
        syns = [i for i in self.D if 'SYN' in i[6]]
        fins = [i for i in self.D if 'FIN' in i[6]]
        
        return (len(syns) >= 1) and (len(fins) >= 1)
    
    def is_established(self):
        """
        If a TCP connection’s first segment is not SYN, we consider it established before the trace capture
        """
        return not "SYN" in self.D[0][6]

    def num_RST_connections(self):
        """
        the number of reset TCP connections observed in the trace
        """
        return(len([i for i in self.D if 'RST' in i[6]]))


    def get_duration(self, dur_only = False):
        """the starting time, ending time, and duration of each complete connection"""
        first_syn_idx = None
        for i in range(len(self.D)):
            if 'SYN' in self.D[i][6]:
                first_syn_idx = i
                break

        last_fin_idx = None
        for i in range(len(self.D)):
            if 'FIN' in self.D[i][6]:
                last_fin_idx = i

        start_time = self.D[first_syn_idx][7] 
        end_time = self.D[last_fin_idx][7]    

        # Calculate relative times by subtracting the abs_start_time
        relative_start_time = start_time - self.abs_start_time
        relative_end_time = end_time - self.abs_start_time
        duration = end_time - start_time

        if dur_only:
            return duration
                
        return [relative_start_time, relative_end_time, duration]

    def tranmission_summary(self):
        """
        returns a 6 element list
        1. Number of packets sent from Source to Destination:
        2. Number of packets sent from Destination to Source:
        3. Total number of packets:
        4. Number of data bytes sent from Source to Destination:
        5. Number of data bytes sent from Destination to Source:
        6. Total number of data bytes:
        """
        S = [pack for pack in self.D if pack[0] == self.ip_a]
        D = [pack for pack in self.D if pack[0] == self.ip_b]
        num_src_to_dest = len(S)
        num_dest_to_src = len(D)
        total_packets =  len(self.D)
    
        bytes_src_to_dest = sum([pack[9] for pack in S])
        bytes_dest_to_src = sum([pack[9] for pack in D])
        total_bytes = bytes_src_to_dest + bytes_dest_to_src
        
        return [num_src_to_dest,num_dest_to_src,total_packets,bytes_src_to_dest, bytes_dest_to_src,total_bytes]

    def connection_summary(self):
        s = f"Connection {self.idx}:\n"
        s += f"Source Address: {self.ip_a}\n"
        s += f"Destination Address: {self.ip_b}\n"
        s += f"Source Port : {self.port_a}\n"
        s += f"Destination Port : {self.port_b}\n"

        if self.is_complete():
            st,end,dur = self.get_duration()
            s += f"Start Time : {st} \n"
            s += f"Duration :   {dur} \n"
            s += f"End Time :   {end} \n"

            TS = self.tranmission_summary()
            s+= f"Number of packets sent from Source to Destination: {TS[0]}\n"
            s+= f"Number of packets sent from Destination to Source: {TS[1]}\n"
            s+= f"Total number of packets: {TS[2]}\n"
            s+= f"Number of bytes from Source to Destination: {TS[3]}\n"
            s+= f"Number of bytes from Destination to Source: {TS[4]}\n"
            s+= f"Total number of bytes: {TS[5]}\n"
            s+= f"END"
        s += '\n' + "+" * 25


        return s

    def is_departing_package(self, i):

        pack = self.D[i]
        return pack[0] == self.ip_a and "RST" not in pack[6] and pack[6] != ["ACK"]


    def get_RTTs(self):
        """
        returns a list containing the RTT
        """
        time_list = []
        for i in range(len(self.D)):
            rtt = self.__RTT(i)
            if rtt is not None:
                time_list.append(rtt)

        return time_list

        

    def __RTT(self, i):
        """
        Calculate the RTT of the ith packet.
        """
        if not self.is_departing_package(i):
            return None

        
        seq_num = self.D[i][4]
        length = self.D[i][8]
        
        # Check if the packet is a SYN packet and adjust the expected ACK number accordingly
        is_syn_packet = self.D[i][6] == ['SYN'] # Assuming SYN flag information is in D[i][6]; adjust if needed
        is_fin_ack_packet = self.D[i][6] == ['FIN', 'ACK']
        exp_ack_num = seq_num + length + (1 if (is_syn_packet or is_fin_ack_packet )else 0)

        # print(f"{self.D[i][6]}: {seq_num} : {exp_ack_num}")

        ack_pack = [p for p in self.D if p[5] == exp_ack_num]
        if len(ack_pack) == 0:
            return None

        return abs(ack_pack[0][7] - self.D[i][7])
        
    def num_packets(self):
        return len(self.D)
    


        

