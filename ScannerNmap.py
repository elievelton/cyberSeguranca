import nmap  # Importa a biblioteca 'nmap', que permite usar o Nmap (um popular scanner de segurança) em Python.

def scan_ports(target):
    nm = nmap.PortScanner()  # Cria uma instância do objeto 'PortScanner' da biblioteca nmap.
    nm.scan(target, '1-1024')  # Inicia uma varredura no alvo especificado ('target') nas portas de 1 a 1024.

    for host in nm.all_hosts():  # Loop através de todos os hosts encontrados na varredura.
        print(f"Host: {host} ({nm[host].hostname()})")  # Imprime o endereço do host e seu nome (se disponível).
        print(f"State: {nm[host].state()}")  # Imprime o estado do host (por exemplo, 'up' se estiver online).

        for proto in nm[host].all_protocols():  # Loop através de todos os protocolos encontrados no host.
            print(f"----------\n{proto}")  # Imprime o nome do protocolo.
            lport = nm[host][proto].keys()  # Obtém todas as portas associadas ao protocolo.

            for port in lport:  # Loop através de todas as portas e imprime o número da porta e seu estado.
                print(f"port: {port} state: {nm[host][proto][port]['state']}")

# Chama a função 'scan_ports' com o endereço IP '138.185.188.45' como alvo da varredura.
scan_ports('138.185.188.45')