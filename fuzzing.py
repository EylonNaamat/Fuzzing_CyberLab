from itertools import count
from tkinter.tix import COLUMN
from scapy.all import *
from simplejson import load

while 1:
    packet = sniff(iface="enp0s8",filter="tcp and port 22", count=1)
    print(packet[0][3])
    print(str(packet[0][3]))


