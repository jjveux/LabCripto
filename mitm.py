import sys
from collections import Counter
from termcolor import colored
from scapy.all import rdpcap, ICMP

# Probabilidades de ocurrencia por letra en español
probabilidades = {
    'a': 0.125, 'b': 0.022, 'c': 0.045, 'd': 0.050, 'e': 0.127, 'f': 0.010, 'g': 0.015, 'h': 0.007, 'i': 0.060,
    'j': 0.003, 'k': 0.0004, 'l': 0.050, 'm': 0.031, 'n': 0.067, 'ñ': 0.003, 'o': 0.086, 'p': 0.022, 'q': 0.008,
    'r': 0.068, 's': 0.079, 't': 0.046, 'u': 0.030, 'v': 0.010, 'w': 0.001, 'x': 0.002, 'y': 0.010, 'z': 0.005
}

def calcular_frecuencia_letras(texto):
    contador = Counter(texto)
    frecuencias = {}
    for letra, probabilidad in probabilidades.items():
        frecuencia = contador.get(letra, 0)
        frecuencias[letra] = frecuencia
    return frecuencias

def desencriptar_cesar(cifrado, corrimiento):
    mensaje = ""
    for letra in cifrado:
        if letra.isalpha():
            nueva_letra = chr(((ord(letra) - corrimiento - ord('a')) % 26) + ord('a'))
            mensaje += nueva_letra
        else:
            mensaje += letra
    return mensaje

def main():
    if len(sys.argv) != 2:
        print("Uso: python programa.py archivo.pcapng")
        sys.exit(1)

    archivo_pcapng = sys.argv[1]

    try:
        paquetes = rdpcap(archivo_pcapng)
    except Exception as e:
        print("Error al leer el archivo pcapng:", str(e))
        sys.exit(1)

    mensajes = []

    for paquete in paquetes:
        if paquete.haslayer(ICMP) and (paquete[ICMP].type == 8 or paquete[ICMP].type == 13):
            icmp_payload = paquete[ICMP].load
            primer_byte = chr(icmp_payload[0]) if icmp_payload else ''  # Convertir el entero en un carácter
            mensajes.append(primer_byte)

    mensaje_cifrado = ''.join(mensajes)

    mensajes_probabilidad = []

    for corrimiento in range(1, 27):
        mensaje_desencriptado = desencriptar_cesar(mensaje_cifrado, corrimiento)
        frecuencias = calcular_frecuencia_letras(mensaje_desencriptado)
        probabilidad = sum([frecuencias[letra] * probabilidades[letra] for letra in frecuencias])
        mensajes_probabilidad.append((mensaje_desencriptado, probabilidad, corrimiento))

    mensajes_probabilidad.sort(key=lambda x: x[1], reverse=True)
    mensaje_ganador, _, corrimiento_ganador = mensajes_probabilidad[0]

    print("\nMensajes posibles (según frecuencia de letras en español):")
    for mensaje, _, corrimiento in mensajes_probabilidad:
        mensaje_color = colored(mensaje, 'green') if mensaje == mensaje_ganador else mensaje
        print(f"Mensaje: {mensaje_color}, Corrimiento: {corrimiento}")

    print("\nMensaje más probable:")
    print(colored(mensaje_ganador, 'green'))
    print(f"Corrimiento utilizado: {corrimiento_ganador}")

if __name__ == "__main__":
    main()

