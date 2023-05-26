from scapy.all import *

# Variáveis globais para armazenar o nome do arquivo e os dados recebidos
filename = None
filedata = b""

def process_packet(packet):
    global filename, filedata

    # Verifique se o pacote é ICMP
    if packet.haslayer(ICMP):
        icmp = packet.getlayer(ICMP)
        # Extraia os dados e tente decodificar como utf-8
        try:
            data = icmp.load.decode('utf-8')

            # Se a mensagem começa com FILE=, pegue o nome do arquivo
            if data.startswith("FILE="):
                filename = data[5:]
                print(f"Recebendo arquivo: {filename}")
                filedata = b""  # Reseta os dados do arquivo para o novo arquivo
            # Se a mensagem é "FIM", salve os dados recebidos no arquivo
            elif data == "FIM":
                if filename is not None:
                    with open(filename, "wb") as f:
                        f.write(filedata)
                    print(f"Arquivo {filename} salvo com sucesso!")
                else:
                    print("Mensagem 'FIM' recebida, mas nenhum arquivo estava sendo recebido.")
            # Caso contrário, adicione os dados ao buffer do arquivo
            else:
                filedata += icmp.load
        except UnicodeDecodeError:
            print("Não foi possível decodificar o conteúdo em utf-8.")

def main():
    # Inicie o sniffer
    sniff(filter="icmp and icmp[icmptype] == 8", prn=process_packet, iface="vmnet8")

if __name__ == "__main__":
    main()
