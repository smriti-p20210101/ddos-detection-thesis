from scapy.fields import BitField


# Define the ddosd_t header format
ddosd_t =(
    BitField("packet_num",0, 32),
    BitField("src_entropy",0, 32),
    BitField("src_ewma",0, 32),
    BitField("src_ewmmd",0, 32),
    BitField("dst_entropy",0, 32),
    BitField("dst_ewma",0, 32),
    BitField("dst_ewmmd",0, 32),
    BitField("alarm",0, 8),
    BitField("ether_type",0, 16)
)

def main():
    # Read the packet capture file and extract the ddosd_t header fields
    packets = rdpcap("answer")
    print("hi")
    for packet in packets:
        if Ether in packet and packet[Ether].type == 0x6605:
            ddosd = ddosd_t(packet[Raw].load)
            print("packet_num: ", ddosd.packet_num)
            print("src_entropy: ", ddosd.src_entropy)
            print("src_ewma: ", ddosd.src_ewma)
            print("src_ewmmd: ", ddosd.src_ewmmd)
            print("dst_entropy: ", ddosd.dst_entropy)
            print("dst_ewma: ", ddosd.dst_ewma)
            print("dst_ewmmd: ", ddosd.dst_ewmmd)
            print("alarm: ", ddosd.alarm)
            print("ether_type: ", hex(ddosd.ether_type))

if __name__ == "_main_":
    main()
