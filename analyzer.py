from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
import os
if not os.path.exists("capture_logs"):
    os.makedirs("capture_logs")

def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] Protocol: {proto} | Src: {ip_src} -> Dst: {ip_dst}"

        print(log_line)

      
        with open("capture_logs/log.txt", "a") as log_file:
            log_file.write(log_line + "\n")

def start_sniffing():
    print("[*] Starting packet capture. Press Ctrl+C to stop.\n")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
