from scapy.all import sniff, wrpcap

captured_packets = []

def process_packet(packet):
    print(packet.summary())
    captured_packets.append(packet)

def main():
    print("Starting packet capture...")
    try:
        sniff(prn=process_packet, count=10)  # Change count to 0 for continuous capture
    except Exception as e:
        print(f"An error occurred during packet capture: {e}")
    finally:
        if captured_packets:
            wrpcap('captured_packets.pcap', captured_packets)
            print("Captured packets saved to 'captured_packets.pcap'.")
        else:
            print("No packets were captured.")

if __name__ == "__main__":
    main()