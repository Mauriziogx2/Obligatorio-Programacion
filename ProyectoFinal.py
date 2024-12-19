import random
import os

def mostrar_menu():
    print("\n" + "=" * 30)
    print("    Menú de Ciberseguridad")
    print("=" * 30)
    print("1. Cifrado Cesar")
    print("2. Descifrado Cesar")
    print("3. Generador de contraseñas")
    print("4. Verificador de contraseñas")
    print("5. Adivinar Pin con fuerza bruta")
    print("6. Salir")
    print("=" * 30)

def limpiar_pantalla():
    """Limpia la pantalla para una mejor experiencia visual."""
    os.system("cls" if os.name == "nt" else "clear")
    
def cifrar_cesar(texto, desplazamiento):
    """
    Cifra un texto usando el cifrado César con un desplazamiento dado.
    """
    resultado = ""
    
    for char in texto:
        if char.isalpha():  # Solo cifrar letras
            base = ord('A') if char.isupper() else ord('a')
            # Calcular la nueva posición con desplazamiento
            nueva_pos = (ord(char) - base + desplazamiento) % 26
            resultado += chr(base + nueva_pos)
        else:
            # Mantener caracteres no alfabéticos sin cambios
            resultado += char
    
    return resultado

def descifrar_cesar(texto, desplazamiento):
    """
    Descifra un texto cifrado con el cifrado César.
    """
    return cifrar_cesar(texto, -desplazamiento)

def generar_contraseña(longitud):
    """
    Genera una contraseña segura que cumple con ciertos requisitos:
    - Al menos 8 caracteres.
    - Al menos una letra mayúscula.
    - Al menos una letra minúscula.
    - Al menos un número.
    - Al menos un carácter especial.
    - La letra 'ñ' también es válida.
    """
    if longitud < 8:
        return "La longitud mínima para una contraseña segura es 8 caracteres."

    # Definir los conjuntos de caracteres válidos utilizando listas (secuelas)
    letras_mayusculas = list("ABCDEFGHIJKLMNÑOPQRSTUVWXYZ")
    letras_minusculas = list("abcdefghijklmnñopqrstuvwxyz")  # Añadimos 'ñ' a las minúsculas
    numeros = list("0123456789")
    caracteres_especiales = list("!@#$%^&*()_+[]{}|;:,.<>?/~")

    # Generar una contraseña mientras no cumpla con los requisitos de seguridad
    while True:
        # Asegurarse de que la contraseña tenga al menos un carácter de cada tipo
        contraseña = random.choice(letras_mayusculas) + random.choice(letras_minusculas) + random.choice(numeros) + random.choice(caracteres_especiales)

        # Rellenar con caracteres aleatorios hasta alcanzar la longitud deseada
        todos_los_caracteres = letras_mayusculas + letras_minusculas + numeros + caracteres_especiales
        contraseña += ''.join(random.choice(todos_los_caracteres) for _ in range(longitud - 4))

        # Mezclar los caracteres para mayor aleatoriedad
        contraseña_segura = ''.join(random.sample(contraseña, len(contraseña)))

        # Verificar si cumple con los requisitos
        if (any(c.isupper() for c in contraseña_segura) and
            any(c.islower() for c in contraseña_segura) and
            any(c.isdigit() for c in contraseña_segura) and
            any(c in caracteres_especiales for c in contraseña_segura)):
            return contraseña_segura
        
def guardar_contraseña_en_archivo(contraseña):
    """
    Guarda una contraseña generada en un archivo de texto.
    """
    with open("contrasenas_generadas.txt", "a") as archivo:
        archivo.write(contraseña + "\n")
        
def verificar_contrasena(contraseña):
    """
    Verifica si una contraseña cumple con las reglas de seguridad:
    - Al menos 8 caracteres.
    - Al menos una letra mayúscula.
    - Al menos una letra minúscula.
    - Al menos un número.
    - Al menos un carácter especial.
    """
    if len(contraseña) < 8:
        return "La contraseña debe tener al menos 8 caracteres."
    if not any(char.isupper() for char in contraseña):
        return "Debe incluir al menos una letra mayúscula."
    if not any(char.islower() for char in contraseña):
        return "Debe incluir al menos una letra minúscula."
    if not any(char.isdigit() for char in contraseña):
        return "Debe incluir al menos un número."
    if not any(char in "!@#$%^&*()_+[]{}|;:,.<>?/~" for char in contraseña):
        return "Debe incluir al menos un carácter especial."
    return "La contraseña es segura."

def fuerza_bruta_pin(pin_secreto):
    """
    Simula un ataque de fuerza bruta para adivinar un PIN numérico.
    """
    intentos = 0
    for posible_pin in range(10000):  # PIN de 4 dígitos
        intentos += 1
        if posible_pin == pin_secreto:
            return intentos, posible_pin
    return intentos, None

def main():
    while True:
        limpiar_pantalla()  # Limpia la pantalla antes de mostrar el menú
        mostrar_menu()
        opcion = input("\nSeleccione una opción: ").strip()
        
        match opcion:
            case '1':  # Cifrar texto
                limpiar_pantalla()
                print("Cifrado Cesar")
                texto = input("Ingrese el texto a cifrar: ")
                desplazamiento = int(input("Ingrese el desplazamiento (ejemplo: 3): "))
                texto_cifrado = cifrar_cesar(texto, desplazamiento)
                print(f"Texto cifrado: {texto_cifrado}")
                input("\nPresione Enter para continuar...")
            
            case '2':  # Descifrar texto
                limpiar_pantalla()
                print("Descifrado Cesar")
                texto = input("Ingrese el texto a descifrar: ")
                desplazamiento = int(input("Ingrese el desplazamiento (ejemplo: 3): "))
                texto_descifrado = descifrar_cesar(texto, desplazamiento)
                print(f"Texto descifrado: {texto_descifrado}")
                input("\nPresione Enter para continuar...")
            
            case '3':  # Generador de contraseñas
                limpiar_pantalla()
                print("Generador de contraseñas")
                longitud = int(input("Ingrese la longitud de la contraseña: "))
                contraseña_generada = generar_contraseña(longitud)
                print(f"Contraseña generada: {contraseña_generada}")
                guardar_contraseña_en_archivo(contraseña_generada)
                input("\nPresione Enter para continuar...")
            
            case '4':  # Verificador de contraseñas
                limpiar_pantalla()
                print("Verificador de contraseñas")
                contrasena = input("Ingrese la contraseña a verificar: ")
                print(verificar_contrasena(contrasena))
                input("\nPresione Enter para continuar...")
            
            case '5':  # Adivinar PIN con fuerza bruta
                limpiar_pantalla()
                print("Adivinar PIN con fuerza bruta")
                pin_secreto = int(input("Ingrese un PIN secreto (4 dígitos): "))
                intentos, pin_encontrado = fuerza_bruta_pin(pin_secreto)
                print(f"PIN encontrado: {pin_encontrado} en {intentos} intentos.")
                input("\nPresione Enter para continuar...")
            
            case '6':  # Salir
                limpiar_pantalla()
                print("Saliendo del programa...")
                break
            
            case _:  # Opción no válida
                print("Opción no válida. Por favor, intente de nuevo.")
                input("\nPresione Enter para continuar...")
                
    
if __name__ == "__main__":
    main()