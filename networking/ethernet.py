import socket
import struct
from general import *

#analyses the ethernet frame
#destination
#source
#type
#payload - will be further broken down
#of the data
class Ethernet:
    def __init__(self, raw_data):
    	#! - network data structure, converting big indian to little indian for compatiblity 
    	#6s means 6 byte 
    	#H means small insigned integer
    	#look at the first 14 bytes
    	#
    	#Unpacks the 1 and 0 of binary data
        dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
        #formats to human readerable form
        #of mac address
        self.dest_mac = get_mac_addr(dest)
        self.src_mac = get_mac_addr(src)
        #convert and make sure we either big or small indian
        #for compatible
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]



