from collections import defaultdict

from scapy.layers.inet import IP, TCP


def _flags(pkt_tcp):
    return str(pkt_tcp.flags)


def detect_port_scans(packets, window_seconds=10, port_threshold=15):
    """Aponta IPs que tocam muitas portas distintas num intervalo curto.

    Port scan = uma origem batendo em varias portas de um alvo em pouco tempo.
    Tocar 3 portas e trafego normal; tocar 20 portas em segundos e varredura.

    Classificacao:
      - SYN scan (stealth): a origem so manda SYN, nunca completa o handshake
      - connect scan: a origem completa o 3-way handshake (manda ACK depois)
    """
    # por origem: lista de (tempo, porta_destino)
    by_src = defaultdict(list)
    sent_ack = defaultdict(bool)

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        flags = _flags(tcp)
        t = float(pkt.time)
        if flags == "S":  # SYN puro (inicio de tentativa)
            by_src[ip.src].append((t, tcp.dport))
        if "A" in flags and "S" not in flags:
            # ACK sem SYN = origem completou handshake em algum momento
            sent_ack[ip.src] = True

    alerts = []
    for src, attempts in by_src.items():
        attempts.sort()
        times = [a[0] for a in attempts]

        # janela deslizante: maior numero de portas DISTINTAS no intervalo
        start = 0
        best = set()
        for end in range(len(attempts)):
            while times[end] - times[start] > window_seconds:
                start += 1
            distinct = set(a[1] for a in attempts[start:end + 1])
            if len(distinct) > len(best):
                best = distinct

        if len(best) >= port_threshold:
            scan_type = "connect scan" if sent_ack[src] else "SYN scan (stealth)"
            alerts.append({
                "src": src,
                "ports_hit": len(best),
                "total_syn": len(attempts),
                "scan_type": scan_type,
                "first_seen": times[0],
                "last_seen": times[-1],
                "sample_ports": sorted(best)[:10],
            })

    alerts.sort(key=lambda a: a["ports_hit"], reverse=True)
    return alerts
