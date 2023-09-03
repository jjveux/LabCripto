import sys

def cifrado_cesar(palabra, clave):
    resultado = ""
    for letra in palabra:
        if letra.isalpha():
            offset = ord('a') if letra.islower() else ord('A')
            resultado += chr((ord(letra) - offset + clave) % 26 + offset)
        else:
            resultado += letra
    return resultado

if len(sys.argv) != 3:
    print("Uso: python cifrado_cesar.py <palabra> <clave>")
    sys.exit(1)

palabra = sys.argv[1]
clave = int(sys.argv[2])

texto_cifrado = cifrado_cesar(palabra, clave)
print(f"Texto cifrado: {texto_cifrado}")
