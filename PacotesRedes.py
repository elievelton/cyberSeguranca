from scapy.all import sniff, IP  # Importa as funções 'sniff' e a camada 'IP' da biblioteca Scapy.
import datetime  # Importa a biblioteca 'datetime' para trabalhar com datas e horas.

# Define uma função chamada 'packet_callback' que recebe um argumento chamado 'packet'.
def packet_callback(packet):
    # Verifica se o pacote capturado possui a camada 'IP'.
    if packet.haslayer(IP):
        # Abre (ou cria, se não existir) o arquivo 'network_log.txt' em modo de adição ('a').
        with open("MonitoramentodaRede.txt", "a") as log:
            # Escreve a data e hora atual, juntamente com os endereços IP de origem e destino do pacote, no arquivo de log.
            log.write(f"{datetime.datetime.now()}: Captured IP: {packet[IP].src} -> {packet[IP].dst}\n")
# Adiciona uma mensagem para indicar que o monitoramento está ativo. 
print("Monitoramento de rede iniciado. Capturando pacotes...")
# Inicia a captura de pacotes chamando a função 'sniff'.
# 'prn=packet_callback' especifica que a função 'packet_callback' deve ser chamada para cada pacote capturado.
# 'store=0' significa que os pacotes capturados não serão armazenados na memória (apenas processados pela função callback).
sniff(prn=packet_callback, store=0)
