import pyshark
import sys

def process_packet(packet):
    try:
        # Abre (ou cria, se não existir) o arquivo 'MonitoramentoHTTP.txt' em modo de adição ('a')
        with open("MonitoramentoHTTP.txt", "a") as log:
            # Exibe informações básicas sobre o pacote
            log.write(f"Pacote capturado: {packet.sniff_time} {packet.sniff_timestamp}\n")
            log.write(f"Origem: {packet.ip.src} -> Destino: {packet.ip.dst}\n")
        
            # Detecção de tráfego HTTP
            if 'HTTP' in packet:
                log.write(f"HTTP encontrado: {packet.http}\n")
        
            # Detecção de tentativas de login Telnet
            if 'TELNET' in packet and 'login' in packet.telnet.data:
                log.write(f"Tentativa de login Telnet detectada: {packet.telnet.data}\n")
            
            # Adiciona uma linha em branco para separar entradas de pacotes diferentes
            log.write("\n")

    except AttributeError as e:
        pass

# Aviso de que o código está sendo executado
print("Iniciando o monitoramento de pacotes em tempo real...")
sys.stdout.flush()

# Captura de pacotes em tempo real na interface especificada
capture = pyshark.LiveCapture(interface='eth0')
capture.apply_on_packets(process_packet)

