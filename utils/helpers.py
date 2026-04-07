import os
import sys
import socket
from scapy.all import ARP, Ether, srp, conf

def check_root():
    if os.geteuid() != 0:
        print("[!] Erro: Este script precisa de privilegios de ROOT (sudo).")
        sys.exit(1)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def run_arp_scan():
    local_ip = get_local_ip()
    ip_range = ".".join(local_ip.split(".")[:-1]) + ".0/24"
    print(f"[*] Escaneando a rede: {ip_range}")
    
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=2, verbose=False)
    
    print("\nIP\t\t\tMAC Address")
    print("-" * 40)
    for snd, rcv in ans:
        print(f"{rcv[ARP].psrc}\t\t{rcv[Ether].src}")

def get_mac(ip, interface):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv[Ether].src
    return None
