from scapy.all import *

packets = rdpcap("SAT-03-11-2018_0144")  # Load the pcap file


for packet in packets:
      packet[IP].src='10.0.2.14'
      packet[IP].dst='10.0.0.1'
      fragments =fragment(packet[IP],fragsize=1300)
      send(fragments, iface='veth0')
