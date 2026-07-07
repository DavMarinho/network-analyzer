import logging

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

TARGET = "192.168.0.10"
ATTACKER = "66.66.66.66"
NORMAL = "192.168.0.25"


def build():
    packets = []
    t = 1_700_000_000.0

    # trafego normal: alguns handshakes completos para portas conhecidas
    for port in (443, 80, 443, 22):
        t += 2
        syn = IP(src=NORMAL, dst=TARGET) / TCP(sport=50000, dport=port, flags="S")
        syn.time = t
        synack = IP(src=TARGET, dst=NORMAL) / TCP(sport=port, dport=50000, flags="SA")
        synack.time = t + 0.01
        ack = IP(src=NORMAL, dst=TARGET) / TCP(sport=50000, dport=port, flags="A")
        ack.time = t + 0.02
        packets += [syn, synack, ack]

    # SYN scan: atacante manda SYN para 30 portas em poucos segundos, sem ACK
    t += 5
    for port in range(1, 31):
        t += 0.1
        pkt = IP(src=ATTACKER, dst=TARGET) / TCP(sport=40000, dport=port, flags="S")
        pkt.time = t
        packets.append(pkt)
        # alvo responde RST (porta fechada) - nao completa handshake
        rst = IP(src=TARGET, dst=ATTACKER) / TCP(sport=port, dport=40000, flags="RA")
        rst.time = t + 0.005
        packets.append(rst)

    return packets


if __name__ == "__main__":
    wrpcap("sample_scan.pcap", build())
    print("sample_scan.pcap gerado.")
