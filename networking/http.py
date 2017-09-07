#Jia-Cong Hou
#3565155
#Network 
#Packet Sniffer
#
#Reference youtube Bucky Robert
#
class HTTP:

    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('utf-8')
        except:
            self.data = raw_data
