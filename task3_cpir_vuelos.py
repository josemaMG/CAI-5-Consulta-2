import time
import random
from phe import paillier

def buscaVuelo(Vuelo_ID_Cliente, Num_Vuelos_Totales, public_key, private_key=None, precios_servidor=None):
    """
    Simulación de Computational Private Information Retrieval (CPIR) usando Paillier.
    """
    # ====== FASE 1: CLIENTE (Aerolínea) ======
    print(f"\n[CLIENTE] Preparando consulta confidencial para el Vuelo ID: {Vuelo_ID_Cliente}")
    start_time = time.time()
    
    # Crea un vector con 0 en todos lados, excepto un 1 en el ID deseado.
    # Luego cifra todos los elementos del vector con la clave pública de Paillier.
    vector_consulta = [0] * Num_Vuelos_Totales
    vector_consulta[Vuelo_ID_Cliente] = 1
    vector_cifrado = [public_key.encrypt(x) for x in vector_consulta]
    
    cliente_time = time.time() - start_time
    print(f"[CLIENTE] Vector de consulta cifrado generado en {cliente_time:.4f} segundos.")
    print("[RED] Enviando vector al servidor...")
    
    # ====== FASE 2: SERVIDOR (Nube) ======
    print("\n[SERVIDOR] Procesando búsqueda sin conocer qué Vuelo ID se busca...")
    start_time = time.time()
    
    # El servidor calcula el producto escalar homomórfico:
    # Se multiplica cada precio en claro por el elemento cifrado del vector, y se suman.
    # Como todos son E(0), aportarán 0 al sumatorio. 
    # El único E(1) multiplicará al Precio buscado aportando E(1 * Precio).
    
    resultado_cifrado = 0 # Inicializar
    for idx, precio_claro in enumerate(precios_servidor):
        # Multiplicación escalar homomórfica y suma aditiva homomórfica
        if idx == 0:
            resultado_cifrado = vector_cifrado[idx] * precio_claro
        else:
            resultado_cifrado += (vector_cifrado[idx] * precio_claro)
            
    servidor_time = time.time() - start_time
    print(f"[SERVIDOR] Procesamiento CPIR completado en {servidor_time:.4f} segundos.")
    print("[RED] Devolviendo Precio cifrado al cliente...")
    
    # ====== FASE 3: CLIENTE (Aerolínea) ======
    start_time = time.time()
    precio_recuperado = private_key.decrypt(resultado_cifrado)
    cliente_dec_time = time.time() - start_time
    print(f"\n[CLIENTE] Precio descifrado en {cliente_dec_time:.4f} segundos.")
    return precio_recuperado, cliente_time + servidor_time + cliente_dec_time

def main():
    print("--- TAREA 2.3: Recuperación de Datos Privados (CPIR Vuelos) ---")
    
    # Escenario: 1273 Vuelos en la base de datos empresarial.
    NUM_VUELOS = 1273
    
    # El Servidor tiene los precios de 1273 vuelos
    # Generamos los precios simulados para la BD (de 50€ a 1500€).
    random.seed(42) # Fijo para reproducibilidad
    precios_servidor = [random.randint(50, 1500) for _ in range(NUM_VUELOS)]
    
    print("\nGenerando claves criptográficas para el CPIR (Paillier 2048-bits)...")
    public_key, private_key = paillier.generate_paillier_keypair(n_length=2048)
    
    vuelo_a_buscar = 404 # Queremos saber el precio del vuelo 404
    precio_real = precios_servidor[vuelo_a_buscar]
    
    # Llamamos al protocolo y medimos
    precio_cpir, total_time = buscaVuelo(
        Vuelo_ID_Cliente=vuelo_a_buscar, 
        Num_Vuelos_Totales=NUM_VUELOS, 
        public_key=public_key, 
        private_key=private_key, 
        precios_servidor=precios_servidor
    )
    
    print("\n--- Resultados de Pruebas de Eficacia (PIR) ---")
    print(f"Precio verificado en texto plano (BD): {precio_real} EUR")
    print(f"Precio obtenido a través de CPIR: {precio_cpir} EUR")
    
    if precio_real == precio_cpir:
        print("EFICACIA COMPROBADA: El precio se ha transmitido correctamente bajo protocolo Zero-Leaks.")
    else:
        print("ERROR en la transmisión PIR.")

    print(f"\nTiempo total de la operación CPIR: {total_time:.4f} segundos para vector de {NUM_VUELOS} opciones.")

if __name__ == "__main__":
    main()
