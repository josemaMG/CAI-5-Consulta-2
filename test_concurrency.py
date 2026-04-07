import time
import concurrent.futures
import random
import os
from datetime import datetime
from phe import paillier

from task2.task2_psi_delincuentes import buscaComunes
from task3.task3_cpir_vuelos import buscaVuelo

def run_homomorphic_task(task_id, public_key, private_key):
    """ Ejecución segura en hilo para la tarea 1 """
    # Payload ligero para conexión masiva (1 gasto por cliente)
    gasto = random.randint(10, 50000)
    
    # Cifrado
    encrypted_gasto = public_key.encrypt(gasto)
    
    # Nube - Suma (simulamos sumar 0 + el gasto)
    encrypted_sum = encrypted_gasto + 0
    
    # Descifrado
    decrypted_sum = private_key.decrypt(encrypted_sum)
    return task_id, (gasto == decrypted_sum)

def run_psi_task(task_id):
    """ Ejecución en concurrencia masiva """
    # Payload ligero: 50 delincuentes, 1 pasajero
    delincuentes = [f"D{x}" for x in range(50)] + ["TARGET"]
    pasajeros = ["TARGET"]
    
    coincidencias, _ = buscaComunes(delincuentes, pasajeros)
    return task_id, (len(coincidencias) == 1)

def run_cpir_task(task_id, public_key, private_key, num_vuelos, precios_servidor):
    """ Ejecución en paralelo de consultas de precios CPIR """
    start = time.time()
    query_vuelo = random.randint(0, num_vuelos - 1)
    
    precio_recuperado, _ = buscaVuelo(
        Vuelo_ID_Cliente=query_vuelo,
        Num_Vuelos_Totales=num_vuelos,
        public_key=public_key,
        private_key=private_key,
        precios_servidor=precios_servidor
    )
    
    success = (precio_recuperado == precios_servidor[query_vuelo])
    return task_id, success

def guardar_log(nombre_archivo, lineas):
    """ Función auxiliar para escribir en la carpeta logs """
    path = os.path.join("logs", nombre_archivo)
    with open(path, "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"\n[{timestamp}] --- NUEVA PRUEBA ---\n")
        f.write("\n".join(lineas) + "\n")

def main():
    os.makedirs("logs", exist_ok=True)
    
    print("=========================================================")
    print(" INICIANDO BANCO DE PRUEBAS DE CONCURRENCIA PARA PETs")
    print(" Guardando resultados en la carpeta 'logs/...'")
    print("=========================================================\n")
    
    # Diferente número de clientes concurrentes a probar (10000 a 30000, saltos de 100)
    escalas_clientes = range(10000, 30001, 100)
    
    # Límite seguro de hilos concurrentes para no colapsar el Sistema Operativo
    MAX_HILOS = 200
    
    # ---------------------------------------------------------
    # PRUEBA 1: CONCURRENCIA EN CIFRADO HOMOMÓRFICO
    # ---------------------------------------------------------
    log_t1 = []
    log_t1.append("=== PRUEBAS DE CARGA MASIVA: SUMA HOMOMÓRFICA ===")
    
    # Generamos la clave global para la sesión una sola vez (escala real cloud)
    print("Generando claves criptográficas de sesión Paillier...")
    public_key_t1, private_key_t1 = paillier.generate_paillier_keypair(n_length=512)
    
    for num_clientes in escalas_clientes:
        print(f"[*] Task 1: Lanzando {num_clientes} clientes simulados...")
        t1_start = time.time()
        exitos = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_HILOS) as executor:
            futures = [executor.submit(run_homomorphic_task, i, public_key_t1, private_key_t1) for i in range(num_clientes)]
            for future in concurrent.futures.as_completed(futures):
                tid, err_free = future.result()
                if err_free: exitos += 1
        
        tiempo_total = time.time() - t1_start
        stats = f"  -> {num_clientes} Clientes | Tiempo Total: {tiempo_total:.2f}s | Éxito: {exitos}/{num_clientes}"
        print(stats)
        log_t1.append(stats)
        
        # Guardar progresivamente para que el usuario pueda ver el log en tiempo real
        guardar_log("task1_results.log", [stats])
        
    print("    [✓] Log Tarea 1 completado.\n")
    
    # ---------------------------------------------------------
    # PRUEBA 2: CONCURRENCIA EN PRIVATE SET INTERSECTION (PSI)
    # ---------------------------------------------------------
    log_t2 = []
    log_t2.append("=== PRUEBAS DE CARGA: DH-PSI DELINCUENTES ===")
    for num_clientes in escalas_clientes:
        print(f"[*] Task 2: Lanzando {num_clientes} validaciones concurrentes DH-PSI...")
        t2_start = time.time()
        exitos = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_HILOS) as executor:
            futures = [executor.submit(run_psi_task, i) for i in range(num_clientes)]
            for future in concurrent.futures.as_completed(futures):
                tid, err_free = future.result()
                if err_free: exitos += 1
                
        tiempo_total = time.time() - t2_start
        stats = f"  -> {num_clientes} Clientes concurrentes | Tiempo Total: {tiempo_total:.2f}s | Éxito: {exitos}/{num_clientes}"
        print(stats)
        log_t2.append(stats)
        guardar_log("task2_results.log", [stats])
        
    print("    [✓] Log Tarea 2 completado.\n")
    
    # ---------------------------------------------------------
    # PRUEBA 3: CONCURRENCIA EN CONSULTAS CPIR
    # ---------------------------------------------------------
    log_t3 = []
    log_t3.append("=== PRUEBAS DE CARGA: CONSULTAS PIR DE VUELOS ===")
    
    print(f"[*] Preparando contexto concurrente para CPIR...")
    NUM_VUELOS = 10 
    precios_servidor = [random.randint(50, 1500) for _ in range(NUM_VUELOS)]
    public_key_t3, private_key_t3 = paillier.generate_paillier_keypair(n_length=512)
    
    for num_clientes in escalas_clientes:
        print(f"[*] Task 3: Lanzando {num_clientes} peticiones CPIR concurrentes...")
        t3_start = time.time()
        exitos = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_HILOS) as executor:
            futures = [
                executor.submit(run_cpir_task, i, public_key_t3, private_key_t3, NUM_VUELOS, precios_servidor) 
                for i in range(num_clientes)
            ]
            for future in concurrent.futures.as_completed(futures):
                tid, err_free = future.result()
                if err_free: exitos += 1
                
        tiempo_total = time.time() - t3_start
        stats = f"  -> {num_clientes} Clientes concurrentes | Tiempo Total: {tiempo_total:.2f}s | Éxito: {exitos}/{num_clientes}"
        print(stats)
        log_t3.append(stats)
        guardar_log("task3_results.log", [stats])
        
    print("    [✓] Log Tarea 3 completado.\n")

    print("=========================================================")
    print(" PRUEBAS DE ESTRÉS FINALIZADAS. REVISE LA CARPETA 'logs'.")
    print("=========================================================")

if __name__ == "__main__":
    main()
