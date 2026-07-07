import argparse
import logging
import sys
from datetime import datetime

logging.getLogger("scapy").setLevel(logging.ERROR)


def build_parser():
    p = argparse.ArgumentParser(
        description="Analisa um arquivo .pcap e aponta varreduras de portas."
    )
    p.add_argument("pcap", help="arquivo .pcap a analisar")
    p.add_argument("-w", "--window", type=int, default=10,
                   help="janela em segundos (padrao 10)")
    p.add_argument("-t", "--threshold", type=int, default=15,
                   help="portas distintas na janela para alertar (padrao 15)")
    return p


def fmt(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def main():
    args = build_parser().parse_args()

    from scapy.utils import rdpcap
    from detector import detect_port_scans

    packets = rdpcap(args.pcap)
    print(f"Pacotes lidos: {len(packets)}\n")

    alerts = detect_port_scans(packets, args.window, args.threshold)
    if not alerts:
        print(f"Nenhum port scan detectado "
              f"(regra: {args.threshold}+ portas em {args.window}s).")
        return 0

    print(f"ALERTAS DE PORT SCAN ({args.threshold}+ portas em {args.window}s)")
    print("-" * 60)
    for a in alerts:
        print(f"Origem     : {a['src']}")
        print(f"Tipo       : {a['scan_type']}")
        print(f"Portas     : {a['ports_hit']} distintas ({a['total_syn']} SYN)")
        print(f"Janela     : {fmt(a['first_seen'])} -> {fmt(a['last_seen'])}")
        print(f"Exemplos   : {a['sample_ports']}")
        print("-" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
