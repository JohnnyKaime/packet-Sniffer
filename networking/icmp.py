import struct

class ICMP:
	#Unpacks Internet Control Message Protocol
	#! - network data structure, converting big indian to little indian for compatability 
    def __init__(self, raw_data):
        self.type, self.code, self.checksum = struct.unpack('! B B H', raw_data[:4])
        self.data = raw_data[4:]
