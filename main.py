import os
import sys
import threading
from scapy.all import conf
from utils.helpers import check_root, get_local_ip, run_arp_scan
from protocols.arp_poison import start_arp_poison
from protocols.dns_spoofer import start_dns_spoofer
from sniffer.capture import start_capture

def setup_system():
    if not os.path.exists("logs"):
        os.makedirs("logs")
    if sys.platform == "linux":
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward > /dev/null 2>&1")

def banner():
    red = "\033[31m"
    reset = "\033[0m"

    print(f"""{red}
    __        ___   _ ____  _____ 
    \ \      / / | | | __ )|  ___|
     \ \ /\ / /| |_| |  _ \| |_   
      \ V  V / |  _  | |_) |  _|  
       \_/\_/  |_| |_|____/|_|    
{reset}
    Wireless Host Behavior Forensics - by: azrael
""")

def modo_ativo():
    print("\n[!] INTERCEPTAR")
    target_ip = input("IP Alvo: ").strip()
    gateway_ip = input("IP Roteador: ").strip()
    domain = input("Dominio: ").strip()
    interface = input("Interface: ").strip() or conf.iface

    if not target_ip or not gateway_ip:
        print("\n[!] Erro: Dados obrigatorios ausentes.")
        return

    start_dns_spoofer(domain)

    try:
        arp_thread = threading.Thread(
            target=start_arp_poison,
            args=(target_ip, gateway_ip, interface)
        )
        arp_thread.daemon = True
        arp_thread.start()
        
        start_capture(interface, target_ip)
    except KeyboardInterrupt:
        print("\n[*] Finalizando sessao...")

def modo_passivo():
    print("\n[+] MONITORAR")
    target_ip = input("IP Filtro: ").strip() or None
    interface = input("Interface: ").strip() or conf.iface
    
    start_capture(interface, target_ip)

def main():
    check_root()
    setup_system()
    
    while True:
        os.system('clear')
        banner()
        print(f"IP Local: {get_local_ip()}")
        print("-" * 45)
        print("1. Modo Ativo   - (ARP Poison + DNS Spoofer + Sniffer)")
        print("2. Modo Passivo - (Sniffer / Monitoramento)")
        print("3. Scanner de Rede - (ARP Scan)")
        print("4. Sair")
        print("-" * 45)

        opcao = input("> ")

        if opcao == "1":
            modo_ativo()
        elif opcao == "2":
            modo_passivo()
        elif opcao == "3":
            print("\n[*] Mapeando dispositivos ativos...")
            run_arp_scan()
            input("\nENTER para voltar...")
        elif opcao == "4":
            sys.exit()

if __name__ == "__main__":
    main()
