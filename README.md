# Network Traffic Analyzer (deteccao de port scan)

Le um arquivo .pcap (captura de rede) e aponta quando alguem esta varrendo as
portas de um host. Um mini-Wireshark focado em uma coisa: achar scan.

## Contexto do desafio

Semana passada eu construi um port scanner (o atacante). Hoje construi o
detector. Entender os dois lados e o que importa: quem sabe atacar sabe defender.

## Como detecta

Port scan e uma origem batendo em muitas portas distintas de um alvo em pouco
tempo. Tocar 3 portas e trafego normal. Tocar 30 portas em segundos e varredura.

O detector usa janela deslizante: conta quantas portas DISTINTAS uma origem
tocou dentro de N segundos. Passou do limite, vira alerta.

### Classificacao do scan

- **SYN scan (stealth)**: a origem so manda pacotes SYN e nunca completa o
  3-way handshake. E o modo "silencioso" (nmap -sS), porque nao abre conexao
  de verdade.
- **connect scan**: a origem completa o handshake (manda o ACK final). Mais
  barulhento e mais facil de logar.

A diferenca aparece nas flags TCP: SYN puro (`S`) sem o ACK (`A`) posterior.

## Por que .pcap e nao captura ao vivo

Captura ao vivo no Windows exige o Npcap instalado e privilegio de admin. Pra
manter o projeto rodavel em qualquer maquina, ele trabalha sobre um arquivo
.pcap (o Scapy le e escreve .pcap sem precisar de Npcap). Mesma deteccao, sem a
dor de configuracao. Um .pcap real do Wireshark funciona igual.

## Como rodar

```bash
pip install -r requirements.txt

# gera um pcap de exemplo (trafego normal + um SYN scan de 30 portas)
python generate_sample.py

# analisa
python cli.py sample_scan.pcap

# ajustando a regra
python cli.py sample_scan.pcap --window 5 --threshold 20
```

## Testes

```bash
python -m pytest test_detector.py -q
```

Cobrem: SYN scan detectado, connect scan classificado, trafego normal ignorado
e scan lento (fora da janela) ignorado.

## Stack

- Python 3.13
- scapy (leitura de pcap e parsing TCP/IP)
