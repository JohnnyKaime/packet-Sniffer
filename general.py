
#Network 
#Packet Sniffer
#
#Reference youtube Bucky Robert
#
import textwrap
# Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
#
#Makes the mac address reader
#Takes in byte address
def get_mac_addr(mac_raw):
	#map loops or runs through mac_raw
	#format each run or each iteration into 2 decimal places
    byte_str = map('{:02x}'.format, mac_raw)
    #joins each 2 digit with a semi colon
    #converts all alphabet letters into upper case
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr


# Formats multi-line data
#word wrap for multiple lines
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
