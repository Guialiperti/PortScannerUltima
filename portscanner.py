import sys
import socket
from scapy.all import *
#Referências: https://www.vivaolinux.com.br/artigo/Construindo-um-portscanner-TCP-com-Python?pagina=2
#comando: python portscanner.py [ip do alvo] [range das portas] [protocolo]

def main():
    print("----Bem-vindo ao PortScanner Ultima, feito por Guilherme Aliperti----\n")
    print("Siga as instruções da tela para selecionar suas preferências\n")
    mode = int(input("Digite 1 para scan de um computador alvo ou 2 para escanear uma rede: "))

    if (mode == 1):
        ip = input("Digite o IP do alvo(ex: 172.20.10.3): ")
        protocol_name = "tcp"
        portas= input(
        "Selecione o Range das portas a serem escaneadas(ex 3:50), deixar vazio para todas: ")
        if len(portas) < 3:
            portas = "1:65536"

        portas = (x for x in range(int(portas.split(":")[0]), int(portas.split(":")[1])+1))

        scan(ip, portas, protocol_name)
    
    elif (mode == 2):
        _subnet = input("Insira o IP da subrede a ser escaneada(ex: 172.20.10.0/28): ")
        _subnet = _subnet.split("/")
        subnet = _subnet[0]
        mask = int(_subnet[1])
        subnet_lsb = int(subnet.split(".")[3])
        mask_range = 2**(32-mask)
        _ips = (x for x in range(
            subnet_lsb, mask_range+1))
        ips = []
        for ip in _ips:
            ips.append(subnet[0:subnet.rfind(".")+1]+str(ip))

        scanNetwork(mask_range, ips)

 
def find_service_name(protocolname, port): 
    service_name = socket.getservbyport(port, protocolname)

    return service_name

def child(ip, port, protocolname):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) 
		s.settimeout(0.3)
		if s.connect_ex((ip, port)) == 0:
			print("{}/tcp open".format(port), end="|")
			print(find_service_name(protocolname, port) + "\n")
	except:
		pass

def udp_child(ip, port):
    protocol_name = 'udp'
    pkt = sr1(IP(dst=ip)/UDP(sport=port, dport=port), timeout=3, verbose=0)
    if pkt == None:
        banner = "Unknown"
        try:
            banner = find_service_name(protocol_name, port)
        except:
            pass
        print("{0}/udp   open | {1}".format(port, banner))

    else:
        if pkt.haslayer(UDP):
            banner = "Unknown"
            try:
                banner = find_service_name(protocol_name, port)
            except:
                pass
            print("{0}/udp   open  {1}".format(port, banner))

def scan(ip, portas, protocolname):
    if protocolname == 'tcp':
        for c in portas:
            child(ip, c, protocolname)
    elif protocolname == 'udp':
        for c in portas:
            udp_child(ip, c)

def scanNetwork(mask_range, ips):
    ports_list = [20, 21, 22, 23, 25, 80, 111, 135, 137, 138, 139, 443, 445, 548, 631, 993, 995, 49152, 62078]
    for ip in ips:
        for port in ports_list:

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                s.settimeout(0.3)
                if s.connect_ex((ip, port)) == 0:
                    print("\nHost no IP {} está ativo".format(ip))
                    break
                s.close()
            except:
                pass

if __name__ == '__main__':
	main()