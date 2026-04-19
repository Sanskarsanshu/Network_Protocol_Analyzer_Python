from scapy.all import *
import logging

logging.basicConfig(filename=''network_traffic.log'', level=logging.INFO, format=''%(asctime)s - %(message)s'')
packet_count = 0

def packet_callback(packet):
    global packet_count
    max_packets = 20
    if packet_count < max_packets:
        logging.info(packet.summary())
        packet_count += 1

def main():
    print("Starting packet capture. Press Ctrl+C to stop.")
    try:
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Packet capture stopped.")

if __name__ == "__main__":
    main()
