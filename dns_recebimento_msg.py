from scapy.all import *
import base64

received_data = ""

def packet_callback(packet):
    global received_data
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # Se o pacote for uma consulta DNS
        qname = packet[DNSQR].qname.decode()  # Obtenha o nome da consulta
        subdomain = qname.split('.', 1)[0]  # Separe o subdomínio
        if subdomain == "INICIO":
            received_data = ""  # Comece a gravação de dados
        elif subdomain == "FIM":
            try:
                print(base64.b64decode(received_data).decode())  # Tente decodificar a mensagem
                received_data = ""  # Limpe os dados recebidos para a próxima mensagem
            except:
                print(f"Cannot decode {received_data}")  # Se a decodificação falhar, imprima a string original
        else:
            received_data += subdomain

sniff(iface="wlp0s20f3", filter="udp port 53", prn=packet_callback, store=0)
