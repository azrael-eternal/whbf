from scapy.all import IP, TCP, UDP, DNS

SUSPICIOUS_PORTS = {
    6667: "IRC (Comum em Botnets)",
    9999: "Deep Throat / Backdoor",
    31337: "Back Orifice (Hacker Tool)",
    4444: "Metasploit / Reverse Shell",
    8888: "C2 Server / Proxy Suspeito",
    5038: "Exploit de Gerenciamento"
}

def parse_packet(pkt):
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "IP"
        
        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            port = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
            
            if port in SUSPICIOUS_PORTS:
                alert_msg = f"\n[!!!] ALERTA DE SEGURANÇA: Port {port} ({SUSPICIOUS_PORTS[port]}) detectada!"
                print(f"\033[91m{alert_msg}\033[0m") # Imprime em Vermelho no terminal
                return f"[ALERT] {src} -> {dst}:{port} [{SUSPICIOUS_PORTS[port]}]"

        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            query = pkt.getlayer(DNS).qd.qname.decode()
            print(f"[DNS] {src} -> {query}")
            return f"[DNS] {src} -> {query}"
        
        elif pkt.haslayer(TCP):
            print(f"[TCP] {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport}")
            return f"[TCP] {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport}"
            
        elif pkt.haslayer(UDP):
            print(f"[UDP] {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}")
            return f"[UDP] {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}"

    return None
