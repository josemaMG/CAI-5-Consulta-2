import time
import random
from task1_crypto_engines import PaillierPHEEngine, TenSEALBFVSHEEngine, TenSEALCKKSFHEEngine

def measure_engine_performance(engine_name, engine, gastos):
    print(f"\n==================================================")
    print(f" Evaluación Criptosistema: {engine_name}")
    print(f"==================================================")
    
    num_clientes = len(gastos)
    gasto_total_real = sum(gastos)
    
    # 1. Cifrado
    print(f"[*] Cifrando {num_clientes} registros de gastos en el origen (cliente)...")
    start_time = time.time()
    encrypted_gastos = [engine.encrypt(g) for g in gastos]
    enc_time = time.time() - start_time
    print(f"    - Tiempo total cifrado: {enc_time:.4f}s ({enc_time/num_clientes:.4f}s / dato)")

    # 2. Suma en la nube (Homomórfica)
    print("[*] Procesando suma homomórfica asíncrona en la Nube Pública...")
    start_time = time.time()
    encrypted_sum = engine.sum(encrypted_gastos)
    sum_time = time.time() - start_time
    print(f"    - Tiempo de suma homomórfica: {sum_time:.4f}s")
    
    # Suma de control (texto claro)
    start_time_clear = time.time()
    sum(gastos)
    sum_time_clear = time.time() - start_time_clear

    # 3. Descifrado en origen
    print("[*] Descifrando el total retornado de la nube...")
    start_time = time.time()
    decrypted_sum = engine.decrypt(encrypted_sum)
    dec_time = time.time() - start_time
    print(f"    - Tiempo de descifrado total: {dec_time:.4f}s")

    # 4. Verificación de precisión 
    # Para FHE basados en floats como CKKS, redondeamos para comparar la efectividad en enteros
    if isinstance(decrypted_sum, float):
        resultado_str = f"{decrypted_sum:.2f} (se redondea a int: {round(decrypted_sum)})"
        match = round(decrypted_sum) == gasto_total_real
    else:
        resultado_str = str(decrypted_sum)
        match = decrypted_sum == gasto_total_real

    print("\n--- Resultados de Integridad ---")
    print(f"Gasto Real en Texto Claro: {gasto_total_real}")
    print(f"Gasto Homomórfico Mágico: {resultado_str}")
    
    if match:
        print(" -> EFICACIA 100%: Suma exacta obtenida desde el entorno cifrado.")
    else:
        print(" -> ERROR/APPROX: Hubo pérdida de precisión en la suma o rebosamiento de ruido.")
        
    return {
        'enc_time': enc_time,
        'sum_time': sum_time,
        'dec_time': dec_time,
        'match': match
    }

def main():
    print("--- CAI 5: TAREA 1. Análisis Multiestrategia de Privacidad Homomórfica ---")
    
    num_clientes = 50
    # Simulamos perfil económico estancado general de la aerolínea
    gastos = [random.randint(10, 50000) for _ in range(num_clientes)]
    
    print("\n[Inicializando motores criptográficos - Puede tardar unos segundos...]")
    
    # Initialize engines
    engine_phe = PaillierPHEEngine(key_size=1024)
    engine_she = TenSEALBFVSHEEngine(plain_modulus=1032193)
    engine_fhe = TenSEALCKKSFHEEngine()

    measure_engine_performance("PHE (Paillier - Aditivo Exacto)", engine_phe, gastos)
    measure_engine_performance("SHE (BFV - Enteros / algo lim. de ruido)", engine_she, gastos)
    measure_engine_performance("FHE (CKKS - Floats Complejos)", engine_fhe, gastos)

if __name__ == "__main__":
    main()
