from collections import defaultdict

ip_counter = defaultdict(int)


def register_packet(src, dst):
    ip_counter[src] += 1
    ip_counter[dst] += 1


def show_stats():
    print("\n=== ESTATÍSTICAS ===")

    sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)

    for ip, count in sorted_ips[:10]:
        print(f"{ip} -> {count} pacotes")
