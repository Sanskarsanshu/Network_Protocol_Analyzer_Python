from scapy.all import *
import time

packet_count = 0
recent_packets = []
traffic_history = []
traffic_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
last_count = 0
last_time = time.time()

def packet_callback(packet):
    global packet_count, recent_packets, traffic_stats
    packet_count += 1
    
    proto_str = "Other"
    if packet.haslayer(TCP):
        traffic_stats["TCP"] += 1
        proto_str = "TCP"
    elif packet.haslayer(UDP):
        traffic_stats["UDP"] += 1
        proto_str = "UDP"
    elif packet.haslayer(ICMP):
        traffic_stats["ICMP"] += 1
        proto_str = "ICMP"
    else:
        traffic_stats["Other"] += 1
        
    src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
    dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
    
    recent_packets.insert(0, {
        "time": time.strftime("%H:%M:%S"),
        "summary": packet.summary()[:80],
        "src": src_ip,
        "dst": dst_ip,
        "proto": proto_str
    })
    
    if len(recent_packets) > 50:
        recent_packets.pop()

def traffic_monitor():
    global packet_count, last_count, last_time, traffic_history
    while True:
        time.sleep(1)
        now = time.time()
        pps = (packet_count - last_count) / (now - last_time)
        last_count = packet_count
        last_time = now
        
        traffic_history.append({"time": time.strftime("%H:%M:%S"), "pps": round(pps)})
        if len(traffic_history) > 60:
            traffic_history.pop(0)

def start_sniffing():
    import threading
    t = threading.Thread(target=traffic_monitor, daemon=True)
    t.start()
    print("Starting packet capture in background...")
    try:
        sniff(prn=packet_callback, store=0)
    except Exception as e:
        print("Sniffer error:", e)

def get_stats():
    return {
        "history": traffic_history,
        "breakdown": traffic_stats,
        "total": packet_count
    }

def get_recent_packets():
    return recent_packets
