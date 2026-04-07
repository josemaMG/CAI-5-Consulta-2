import time
import concurrent.futures
from task1_crypto_engines import PaillierPHEEngine, TenSEALBFVSHEEngine, TenSEALCKKSFHEEngine

def client_task(engine):
    """
    Simula la carga de trabajo de un cliente:
    Empaquetar su gasto y aplicarle el cifrado requerido.
    """
    return engine.encrypt(10) # Sumaremos decenas para evitar variables masivas innecesarias

def test_concurrency_load():
    print("=========================================================================")
    print(" INICIANDO BANCO DE PRUEBAS TEST 3: CONCURRENCIA DE SUMA HOMOMÓRFICA")
    print(" Evaluando esquema mediante concurrencia de 1000 a 5000 peticiones")
    print("=========================================================================\n")
    
    escalas = [1000, 2000, 3000, 4000, 5000]
    
    # Por temas de extrema restricción de consumo de memoria y computación, el Benchmark masivo se hace
    # sobre el algoritmo requerido original (PHE), puesto que TenSEAL (FHE) en 5000 concurrentes 
    # generaría Out-Of-Memory (OOM) matando el proceso del sistema.
    print("[*] Inicializando Crypto Engine (Paillier PHE 512 bits de perfilado para benchmark)...")
    engine = PaillierPHEEngine(key_size=512)
    
    MAX_WORKERS = 200
    
    for num_clientes in escalas:
        print(f"\n---> ESCALA DE PRUEBA: {num_clientes} CLIENTES CONCURRENTES <---")
        
        # 1. Simulación Fase Cliente
        start_client = time.time()
        cifrados = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(client_task, engine) for _ in range(num_clientes)]
            for future in concurrent.futures.as_completed(futures):
                cifrados.append(future.result())
        client_time = time.time() - start_client
        print(f"    -> Tiempo Total Fase Cliente (Distribución en Hilos): {client_time:.2f} s")
        
        # 2. Simulación Fase Nube
        start_cloud = time.time()
        encrypted_total = engine.sum(cifrados)
        cloud_time = time.time() - start_cloud
        print(f"    -> Tiempo Total Fase Nube (Procesar Homomórfico Suma): {cloud_time:.3f} s")
        
        # 3. Validación de consistencia
        real_total = engine.decrypt(encrypted_total)
        expected_total = 10 * num_clientes
        comprobacion = (real_total == expected_total)
        assert comprobacion, f"Fallo al sumar concurrentemente: obtenido {real_total}, esperado {expected_total}"
        
        print(f"    [OK] Integridad validada y garantizada al 100%. Obtenido: {real_total}")
        
    print("\n--- TEST DE ESTRÉS CONCURRENTE FINALIZADO CORRECTAMENTE ---")

if __name__ == "__main__":
    test_concurrency_load()
