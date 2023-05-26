from scapy.all import *
import argparse

def main():
    # Cria o parser e adiciona o argumento para o arquivo e ip
    parser = argparse.ArgumentParser(description="Envia um arquivo via ICMP")
    parser.add_argument("file", help="Nome do arquivo para enviar")
    parser.add_argument("ip", help="Endereço IP de destino")
    args = parser.parse_args()

    # Abra o arquivo e leia o conteúdo
    with open(args.file, "rb") as file:
        data = file.read()

    # Envia o nome do arquivo primeiro
    file_packet = IP(dst=args.ip)/ICMP()/(b"FILE=" + args.file.encode())
    send(file_packet)

    # Divide o conteúdo em partes de 1400 bytes
    chunks = [data[i:i+1400] for i in range(0, len(data), 1400)]

    # Envie um pacote ICMP com cada parte dos dados
    for chunk in chunks:
        packet = IP(dst=args.ip)/ICMP()/Raw(chunk)
        send(packet)

    # Envia a mensagem "FIM" após todos os dados
    end_packet = IP(dst=args.ip)/ICMP()/b"FIM"
    send(end_packet)

if __name__ == "__main__":
    main()
