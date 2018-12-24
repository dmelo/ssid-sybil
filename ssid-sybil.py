from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump
import sys

iface = 'wlp0s20u1mon'         #Interface name here
iface = 'wlp1s0mon'         #Interface name here

class NetConfig:
    def __init__(self, addr1, addr2, addr3, netSSID):
        self.addr1= addr1
        self.addr2= addr2
        self.addr3= addr3
        self.netSSID= netSSID

netList = [
    NetConfig('ff:ff:ff:ff:ff:ff', '22:22:22:22:22:26', '32:22:22:22:22:26', "01. We're no strangers to love"),
    NetConfig('ff:ff:ff:ff:ff:ff', '22:22:22:22:22:27', '32:22:22:22:22:27', "02. You know the rules and so do I"),
    NetConfig('ff:ff:ff:ff:ff:ff', '22:22:22:22:22:28', '32:22:22:22:22:28', "03. A full commitment's what I'm thinking of"),
    NetConfig('ff:ff:ff:ff:ff:ff', '22:22:22:22:22:29', '32:22:22:22:22:29', "04. You wouldn't get this from any other guy"),
    NetConfig('ff:ff:ff:ff:ff:ff', '22:22:22:22:22:2a', '32:22:22:22:22:2a', "05. I just wanna tell you how I'm feeling"),
    NetConfig('ff:ff:ff:ff:ff:ff', '22:22:22:22:22:2b', '32:22:22:22:22:2b', "06. Gotta make you understand"),
    NetConfig('ff:ff:ff:ff:ff:ff', '22:22:22:22:22:20', '32:22:22:22:22:20', '07. Never gonna give you up'),
    NetConfig('ff:ff:ff:ff:ff:ff', '22:22:22:22:22:21', '32:22:22:22:22:21', '08. Never gonna let you down'),
    NetConfig('ff:ff:ff:ff:ff:ff', '22:22:22:22:22:22', '32:22:22:22:22:22', '09. Never gonna run around and desert you'),
    NetConfig('ff:ff:ff:ff:ff:ff', '22:22:22:22:22:23', '32:22:22:22:22:23', '10. Never gonna make you cry'),
    NetConfig('ff:ff:ff:ff:ff:ff', '22:22:22:22:22:24', '32:22:22:22:22:24', '11. Never gonna say goodbye'),
    NetConfig('ff:ff:ff:ff:ff:ff', '22:22:22:22:22:25', '32:22:22:22:22:25', '12. Never gonna tell a lie and hurt you')
]

frameList = [];

for net in netList:
    dot11 = Dot11(
        type=0,
        subtype=8,
        addr1=net.addr1,
        addr2=net.addr2,
        addr3=net.addr3
    )
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID',info=net.netSSID, len=len(net.netSSID))
    rsn = Dot11Elt(ID='RSNinfo', info=(
    '\x01\x00'                 #RSN Version 1
    '\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
    '\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
    '\x00\x0f\xac\x04'         #AES Cipher
    '\x00\x0f\xac\x02'         #TKIP Cipher
    '\x01\x00'                 #1 Authentication Key Managment Suite (line below)
    '\x00\x0f\xac\x02'         #Pre-Shared Key
    '\x00\x00'))               #RSN Capabilities (no extra capabilities)

    frame = RadioTap()/dot11/beacon/essid/rsn
    frame.show()
    print("\nHexdump of frame:")
    hexdump(frame)
    frameList.append(frame)




sendp(frameList, iface=iface, inter=0.0, loop=1)
