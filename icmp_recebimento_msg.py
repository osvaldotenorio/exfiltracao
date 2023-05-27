from scapy.all import *

def process_packet(packet):
    # Verifique se o pacote é ICMP
    if packet.haslayer(ICMP):
        icmp = packet.getlayer(ICMP)
        # Extraia os dados e tente decodificar como utf-8
        try:
            data = icmp.load.decode('utf-8')
            print(f"Data: {data}")
        except UnicodeDecodeError:
            print("Não foi possível decodificar o conteúdo em utf-8.")

def main():
    # Inicie o sniffer
    # Lembrar de trocar o nome da interface de rede em iface de acordo com a que estiver usando
    sniff(filter="icmp and icmp[icmptype] == 8", prn=process_packet, iface="vmnet8")

if __name__ == "__main__":
    main()
