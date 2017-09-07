import struct


class UDP:

    def __init__(self, raw_data):
    	#! - network data structure, converting big indian to little indian for compatability 
        self.src_port, self.dest_port, self.size = struct.unpack('! H H 2x H', raw_data[:8])
        self.data = raw_data[8:]
