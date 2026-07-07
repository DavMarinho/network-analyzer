import logging

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.layers.inet import IP, TCP

from detector import detect_port_scans


def syn(src, dst, dport, t):
    p = IP(src=src, dst=dst) / TCP(sport=40000, dport=dport, flags="S")
    p.time = t
    return p


def ack(src, dst, dport, t):
    p = IP(src=src, dst=dst) / TCP(sport=40000, dport=dport, flags="A")
    p.time = t
    return p


def test_syn_scan_detected():
    pkts = [syn("9.9.9.9", "10.0.0.1", port, 1000 + port * 0.1)
            for port in range(1, 21)]
    alerts = detect_port_scans(pkts, window_seconds=10, port_threshold=15)
    assert len(alerts) == 1
    assert alerts[0]["src"] == "9.9.9.9"
    assert alerts[0]["scan_type"].startswith("SYN scan")


def test_connect_scan_classified():
    pkts = []
    for port in range(1, 21):
        pkts.append(syn("8.8.8.8", "10.0.0.1", port, 1000 + port * 0.1))
        pkts.append(ack("8.8.8.8", "10.0.0.1", port, 1000 + port * 0.1 + 0.01))
    alerts = detect_port_scans(pkts, window_seconds=10, port_threshold=15)
    assert alerts[0]["scan_type"] == "connect scan"


def test_normal_traffic_not_flagged():
    # poucas portas, nao e varredura
    pkts = [syn("7.7.7.7", "10.0.0.1", port, 1000 + port)
            for port in (80, 443, 22)]
    alerts = detect_port_scans(pkts, window_seconds=10, port_threshold=15)
    assert alerts == []


def test_slow_scan_below_window_not_flagged():
    # 20 portas, mas 1 por minuto: fora da janela de 10s
    pkts = [syn("6.6.6.6", "10.0.0.1", port, 1000 + port * 60)
            for port in range(1, 21)]
    alerts = detect_port_scans(pkts, window_seconds=10, port_threshold=15)
    assert alerts == []
