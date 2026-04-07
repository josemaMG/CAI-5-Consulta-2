import time
import hashlib
from Crypto.Util import number

# --- Parámetros globales para DH-PSI ---
# Usamos un número primo grande (2048 bits usualmente, aquí usamos 512 por velocidad de la demo)
PRIME = number.getPrime(512)

def hash_data(data_string):
    """ Hashea el texto de entrada y lo convierte en entero """
    h = hashlib.sha256(data_string.encode('utf-8')).hexdigest()
    return int(h, 16) % PRIME

def encrypt_set(data_list, secret_key):
    """ Aplica exponenciación modular DH: (data^key) mod PRIME """
    return [pow(item, secret_key, PRIME) for item in data_list]

def format_id(id_str):
    """ 
    Normaliza el ID para evitar falsos negativos por espacios o minúsculas.
    Condición de entrada necesaria.
    """
    return str(id_str).strip().upper()

def buscaComunes(Set_de_delincuentes_Claro, Set_de_pasajeros_vuelo_Claro):
    """
    Simulación del Protocolo DH-PSI (Diffie-Hellman Private Set Intersection)
    """
    print("\nIniciando protocolo DH-PSI...")
    # Generación de claves privadas que nunca se comparten
    Key_A = number.getRandomRange(2, PRIME - 2) # Clave privada de Autoridades
    Key_L = number.getRandomRange(2, PRIME - 2) # Clave privada de Aerolinea
    
    # 0. Preparación y Hashing
    start_time = time.time()
    hash_delincuentes = [hash_data(format_id(x)) for x in Set_de_delincuentes_Claro]
    hash_pasajeros = [hash_data(format_id(x)) for x in Set_de_pasajeros_vuelo_Claro]
    
    # 1. Autoridades cifran su set y la Aerolinea cifra el suyo
    A_enc = encrypt_set(hash_delincuentes, Key_A)
    L_enc = encrypt_set(hash_pasajeros, Key_L)
    
    # Se intercambian los sets cifrados (Simulado)
    # 2. Autoridades cifran el set de la Aerolinea y Aerolinea cifra el de Autoridades
    L_double_enc = encrypt_set(L_enc, Key_A) # (Pasajero^Key_L)^Key_A
    A_double_enc = encrypt_set(A_enc, Key_L) # (Delincuente^Key_A)^Key_L
    
    # 3. Intersección final (cualquier parte que tenga ambas listas doblemente cifradas puede hacerlo)
    # Por propiedad conmutativa: (M^Key_L)^Key_A == (M^Key_A)^Key_L mod PRIME
    set_A_final = set(A_double_enc)
    set_L_final = set(L_double_enc)
    
    comunes_doble_cifrado = set_A_final.intersection(set_L_final)
    end_time = time.time()
    
    print(f"Búsqueda finalizada. Tiempo de protocolo: {end_time - start_time:.4f} segundos.")
    
    # Para saber quiénes son los comunes, las autoridades (quienes iniciaron la búsqueda) 
    # revisan cuáles de sus elementos originales dieron un doble cifrado que está en la intersección
    match_reales = []
    for i, orig in enumerate(Set_de_delincuentes_Claro):
        if A_double_enc[i] in comunes_doble_cifrado:
            match_reales.append(orig)
            
    return match_reales, end_time - start_time

def main():
    print("--- TAREA 2.2: Privacidad contra Delincuencia y Terrorismo (DH-PSI) ---")
    
    # Simulación de datos
    # 10.000 Delincuentes por parte de las autoridades
    delincuentes = [f"PASS{x:06d}" for x in range(10000)]
    delincuentes.append("PASS-TERROR1")
    delincuentes.append("PASS-TERROR2")
    
    # 250 Pasajeros en el vuelo
    pasajeros = [f"PAS_NO_CULPABLE_{x}" for x in range(248)]
    pasajeros.append("pass-terror1  ") # Demostrando normalización
    pasajeros.append("PASS-TERROR2")
    
    print(f"Autoridades disponen de {len(delincuentes)} delincuentes en su base de datos confidencial.")
    print(f"Vuelo contiene {len(pasajeros)} pasajeros con identidades confidenciales.")
    
    # Ejecutamos el Protocolo
    coincidencias, tiempo_ejecucion = buscaComunes(delincuentes, pasajeros)
    
    print(f"\nResultados del PSI:")
    print(f"Se han encontrado {len(coincidencias)} delincuentes en el vuelo.")
    print(f"Delincuentes identificados: {coincidencias}")
    
    # Analisis de eficiencia
    print("\n--- Resultados de Pruebas de Eficiencia ---")
    print(f"Tiempo total: {tiempo_ejecucion:.4f} segundos para evaluar vuelo completo contra DB externa protegida.")

if __name__ == "__main__":
    main()
