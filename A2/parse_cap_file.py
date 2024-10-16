import struct

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

            
            src_port, dest_port, seq, ack, flags, tcp_payload = parse_tcp_header(payload)

            l = [src_ip, src_port, dest_ip, dest_port, seq, ack, bin(flags)]

            L.append(l)

    return L

def get_unique_conns(L):
    return set([tuple(l[:4]) for l in L])
# Example usage
L= parse_cap_file('sample-capture-file.cap')

print(f"len(L) = {len(L)}")
print(f"num conns = {get_unique_conns(L)}")


