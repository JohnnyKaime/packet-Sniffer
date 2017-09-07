#Jia-Cong Hou
#3565155
#Network 
#Packet Sniffer
#
#Reference youtube Bucky Robert
#
import socket
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


#Breaking up IP packet into different known protocols
#Structure of Ethernet Frame
#8 - 6 - 6 - 2 - 46 ~ 1500 - 4

#8 byte to sync, makes sure computer and router are in sync
#6 byte of sender mostly user computer or router and vice versa
#6 byte of receiver mostly router or user computer and vice versa
#2 byte of ethernet type of protocol
#   0x0800 IP4 Frame
#   0x0806 ARP Request / Response
#   0x86DD IP6 Frame
#Payload main data
#4 byte of Cyclic Redundancy Check, check if the data received got any errors

def main():
    #pcap is used to live capture network traffic
    pcap = Pcap('capture.pcap')
    #Creates a socket using 
    #Check that its compatible and make sure its in little or big indian
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    #Keeps looping and capturing data
    while True:
        #buffer size is set to 65535
        raw_data, addr = conn.recvfrom(65535)
        #storing the data
        #capturing it
        pcap.write(raw_data)
        eth = Ethernet(raw_data)
        #{} place order for each variable 
        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        #Unpacking IP Headers
        # IPv4
        #Make sure using regular internet traffic
        #which is IPv4
        if eth.proto == 8:
            #calling class ip4
            #passing capture data into class
            #analysing and using its methods
            ipv4 = IPv4(eth.data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

            # ICMP
            if ipv4.proto == 1:
                #after analysing the capture data
                #ipv4 determines which type of protocol the prackage is from
                #1 for ICMP
                ipv4 = IPv4(eth.data)
                icmp = ICMP(ipv4.data)
                #analyses using icmp class
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                print(TAB_2 + 'ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp.data))

            # TCP
            elif ipv4.proto == 6:
                #after analysing the capture data
                #ipv4 determines which type of protocol the prackage is from
                #6 for ICMP
                tcp = TCP(ipv4.data)
                #analyses using icmp class
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                #at least some thing is capture
                if len(tcp.data) > 0:

                    #protocol port for HTTP is 80
                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            #analyses using icmp class
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp.data))

            #analyses using UDP class
            # UDP
            #17 for UDP
            elif ipv4.proto == 17:
                #analyses using UDP class
                udp = UDP(ipv4.data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

            # Other
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, ipv4.data))

        else:
            #this remaining is the payload of data
            #data that meaningless or which we cant yet interpret 
            print('Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, eth.data))
    #closing the library after use
    pcap.close()
main()
