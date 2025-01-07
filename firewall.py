import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP
threshold = 40
print(f"Threshold: {threshold}")

def packet_sniff(packet):
    if IP in packet:
        src_ip = packet[IP].src
        packet_counter[src_ip] += 1

        current_time = time.time()
        time_interval = current_time - start_time[0]
        if time_interval >= 1:
            for ip, count in list(packet_counter.items()):
                packet_rate = count / time_interval
                print(f"IP: {ip}, Packet Rate: {packet_rate:.2f}")
                if packet_rate > threshold and ip not in blocked_ip:
                    print(f"Blocking IP: {ip}, Packet Rate: {packet_rate:.2f}")
                    os.system(f"iptables -A INPUT -s {ip} -j DROP")
                    blocked_ip.add(ip)
            packet_counter.clear()
            start_time[0] = current_time

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root")
        sys.exit(1)
    packet_counter = defaultdict(int)
    start_time = [time.time()]
    blocked_ip = set()

    print("Monitoring Network Traffic...")
    sniff(filter="ip", prn=packet_sniff)
