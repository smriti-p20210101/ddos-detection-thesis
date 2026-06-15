from scapy.fields import BitField


# Define the ddosd_t header format
class DDoSd(Packet):
    name = "DDoSd"
    fields_desc = [
        BCDFloatField("src_entropy", 0),
        BCDFloatField("dst_entropy", 0),
        BCDFloatField("meta_alarm", 0),
    ]

def main():
    # Read the packet capture file and extract the ddosd_t header fields
    packets = rdpcap("answer")
    print("hi")
    for packet in packets:
        if Ether in packet and packet[Ether].type == 0x6605:
            ddosd = DDoSd(packet[Raw].load)
            print("src_entropy: ", ddosd.src_entropy)
            print("dst_entropy: ", ddosd.dst_entropy)
            print("alarm: ", ddosd.meta_alarm)

if __name__ == "_main_":
    main()
