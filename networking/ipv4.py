import struct


class IPv4:
    #Unpacking IP header
    def __init__(self, raw_data):
        #Version and Header length
        #Byte wise operations and shift 4 to the right
        version_header_length = raw_data[0]
        self.version = version_header_length >> 4
        #Compare 2 bytes and return the result by 4
        self.header_length = (version_header_length & 15) * 4
        #Right after the header length is the actually data capture
        #! - Make sure byte order is correct
        #formating
        #Data is from 20 bytes onwards
        self.ttl, self.proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.src = self.ipv4(src)
        self.target = self.ipv4(target)
        self.data = raw_data[self.header_length:]

    # Returns properly formatted IPv4 address
    #Format ip4
    def ipv4(self, addr):
        return '.'.join(map(str, addr))
