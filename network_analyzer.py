from scapy.all import *

def main():
    print("Starting packet capture. Press Ctrl+C to stop.")
    try:
        sniff(count=10)
    except KeyboardInterrupt:
        print("Packet capture stopped.")

if __name__ == "__main__":
    main()
