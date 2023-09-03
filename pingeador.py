import sys
import random
from scapy.all import IP, ICMP, send, Raw

def create_ping_packet(identifier, sequence_number, char):
    # Crea un paquete ICMP tipo "echo request"
    packet = IP(dst="8.8.8.8") / ICMP(type="echo-request")

    # Establece el campo identifier y sequence number
    packet.id = identifier
    packet.seq = sequence_number

    # Crea los datos del paquete
    data = bytes([ord(char)])  # Convierte el carácter en bytes
    data += bytes([0] * 2)  # Dos bytes nulos
    data += bytes(range(10, 38))  # Bytes incrementales desde 10 hasta 37

    # Agrega los datos al paquete como carga útil Raw
    packet = packet / Raw(load=data)

    return packet

def main():
    if len(sys.argv) != 2:
        print("Uso: python ping_string.py <cadena>")
        sys.exit(1)

    input_string = sys.argv[1]

    identifier = random.randint(1, 65535)  # Identifier aleatorio
    sequence_number = 1

    ping_packets = []  # Lista para almacenar los paquetes ICMP

    for char in input_string:
        ping_packet = create_ping_packet(identifier, sequence_number, char)
        ping_packets.append(ping_packet)  # Agrega el paquete a la lista
        sequence_number += 1

    # Envía todos los paquetes juntos
    send(ping_packets)

if __name__ == "__main__":
    main()


