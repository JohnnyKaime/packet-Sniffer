import struct

class TCP:
    #Unpack Transimission Control Protocol
    #Most of the times packages will be TCP
    def __init__(self, raw_data):
        ##! - network data structure, converting big indian to little indian for compatability 
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = struct.unpack(
            '! H H L L H', raw_data[:14])
        #Offset + Reserved + TCP Flags is 16 bytes together, one "chunk"
        #Byte shift by 12 and times by 4
        offset = (offset_reserved_flags >> 12) * 4
        #flags are use to communicate
        #data is not send straight flags are use to determine 
        #states such as ready or finish etc
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        self.data = raw_data[offset:]
