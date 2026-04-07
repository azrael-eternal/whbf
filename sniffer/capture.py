import os
import time
from scapy.all import sniff, wrpcap, IP, TCP, UDP, DNS
from sniffer.parser import parse_packet

LOG_DIR = "logs"

def start_capture(interface=None, target_ip=None):
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    pcap_file = f"{LOG_DIR}/capture_{timestamp}.pcap"
    text_log = f"{LOG_DIR}/report_{timestamp}.txt"

    print(f"[*] Sniffer iniciado..: {target_ip if target_ip else 'Rede Toda'}")
    print(f"[*] A guardar evidências em: {LOG_DIR}/")

    def log_and_display(pkt):
        parse_packet(pkt)
        
        wrpcap(pcap_file, pkt, append=True)
        
        if pkt.haslayer(IP):
            with open(text_log, "a") as f:
                info = f"[{time.strftime('%H:%M:%S')}] {pkt[IP].src} -> {pkt[IP].dst}"
                if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                    info += f" | DNS Query: {pkt.getlayer(DNS).qd.qname.decode()}"
                f.write(info + "\n")

    sniff(
        iface=interface,
        filter=f"host {target_ip}" if target_ip else None,
        prn=log_and_display,
        store=0
    )
