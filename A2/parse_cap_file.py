import struct
import datetime

def mac_addr(address_bytes):
    """Convert a MAC address from bytes to human-readable form."""
    return ':'.join(map('{:02x}'.format, address_bytes))

def ip_addr(address_bytes):
    """Convert an IP address from bytes to human-readable form."""
    return '.'.join(map(str, address_bytes))

def parse_ip_header(data):
    """Parse the IP header and extract IP addresses, protocol, and other fields."""
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4  # IHL is the last 4 bits
    ttl, proto, src_ip, dest_ip = struct.unpack('!8xBB2x4s4s', data[:20])
    return ip_addr(src_ip), ip_addr(dest_ip), proto, data[header_length:]

def parse_tcp_header(data):
    """Parse the TCP header and extract ports, sequence numbers, and flags."""
    src_port, dest_port, seq, ack, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4  # Data offset in the first 4 bits
    flags = offset_reserved_flags & 0x01FF  # Last 9 bits are the flags
    return src_port, dest_port, seq, ack, flags, data[offset:]

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
    with open(file_path, 'rb') as f:
        # Skip the global header (24 bytes)
        f.read(24)

        while True:
            # Read the packet header (16 bytes)
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break  # End of file

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', packet_header)
            packet_data = f.read(incl_len)

            # grab the payload from the data section
            payload = packet_data[14:]

            src_ip, dest_ip, proto, payload = parse_ip_header(payload)

            
            src_port, dest_port, seq, ack, flags, payload = parse_tcp_header(payload)
            flags = parse_flags(flags)
            L.append(tuple([src_ip, src_port, dest_ip, dest_port, seq, ack, flags, ts_sec, ts_usec,len(payload)]))

        
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
    D =  sorted(D, key=lambda x: (x[-2], x[-1]))
    return D

class Connection:
    def __init__(self,idx,connection_ids,data):
        self.ID = connection_ids[idx][:4]
        self.D =  [i for i in data if self.ID == i[:4] or self.ID == (i[2],i[3],i[0],i[1])]
        self.D =  sorted(self.D, key=lambda x: (x[-2], x[-1]))
        self.abs_start_time = [data[0][7], data[0][8]]

        
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
    

    def __time_diff(self,t1,t2):
        T = [
            t1[0] - t2[0],
            t1[1] - t2[1]
        ]
        if T[1] < 0:
            T[0] -= 1
            T[1] += 1000000
       
        return T

    def get_duration(self):
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

        start_time = [self.D[first_syn_idx][7], self.D[first_syn_idx][8]]  # [seconds, microseconds]
        end_time = [self.D[last_fin_idx][7], self.D[last_fin_idx][8]]      # [seconds, microseconds]

        # Calculate relative times by subtracting the abs_start_time
        relative_start_time = self.__time_diff(start_time, self.abs_start_time)
        relative_end_time = self.__time_diff(end_time, self.abs_start_time)
        duration = self.__time_diff(end_time, start_time)


                
        return [relative_start_time, relative_end_time, duration]
            
                
