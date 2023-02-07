from scapy.all import *

interface = sys.argv[1]
mac_addr = sys.argv[2]

def print_sig(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                if packet.addr2 == mac_addr.lower():
                    radiotap = packet.getlayer(RadioTap)
                    rssi = radiotap.dBm_AntSignal
                    print("signal strength={}".format(rssi))
                    
sniff(iface=interface, prn=print_sig)
