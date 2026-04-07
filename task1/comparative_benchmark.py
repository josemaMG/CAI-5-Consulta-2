import time
import os
import sys
# Asegurarnos de importar desde la carpeta local actual si se corre desde raíz
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from task1_crypto_engines import PaillierPHEEngine, TenSEALBFVSHEEngine, TenSEALCKKSFHEEngine

def run_benchmark():
    # Nos aseguramos de estar guardando en la carpeta de la raiz general CAI-5-Consulta-2/logs
    logs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
    os.makedirs(logs_dir, exist_ok=True)
    log_path = os.path.join(logs_dir, "task1_comparative.log")
    
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("=========================================================================\n")
        f.write(" REPORTE COMPARATIVO: PHE vs SHE vs FHE (Tarea 1)\n")
        f.write("=========================================================================\n\n")

        print("[*] Generando instancias y public/private keys de Paillier, BFV y CKKS...")
        engines = {
            "PHE (Paillier)": PaillierPHEEngine(key_size=2048),
            "SHE (BFV - TenSEAL)": TenSEALBFVSHEEngine(plain_modulus=1032193),
            "FHE (CKKS - TenSEAL)": TenSEALCKKSFHEEngine()
        }
        
        # Test 1: Precisión y Tiempos en Carga Ligera
        gastos_pequenos = [50]*50 # 2500 total
        f.write("--- TEST 1: CARGA LIGERA MULTIPLE (50 operaciones de gasto bajo) ---\n")
        print("[*] Evaluando Test 1 - Carga Ligera...")
        for name, engine in engines.items():
            start_enc = time.time()
            cifrados = [engine.encrypt(g) for g in gastos_pequenos]
            enc_time = time.time() - start_enc
            
            start_sum = time.time()
            suma = engine.sum(cifrados)
            sum_time = time.time() - start_sum
            
            start_dec = time.time()
            val = engine.decrypt(suma)
            dec_time = time.time() - start_dec
            
            is_match = (round(val) == 2500) if isinstance(val, float) else (val == 2500)
            
            f.write(f"[{name}]\n")
            f.write(f"  - Tiempo Cifrado (x50 obj): {enc_time:.4f}s\n")
            f.write(f"  - Tiempo Procesamiento Nube: {sum_time:.4f}s\n")
            f.write(f"  - Tiempo Descifrado Result: {dec_time:.4f}s\n")
            f.write(f"  - Éxito/Integridad comprobada: {'SI' if is_match else 'NO (Ruido)'}\n\n")
            
        # Test 2: Precisión en Carga Masiva (Millones - Overflow Check)
        gastos_grandes = [1_500_000, 2_000_000, 3_000_000] # Total -> 6,500,000
        f.write("--- TEST 2: VALORES GIGANTES (1.5M, 2M, 3M) ---\n")
        f.write("Propósito: Identificar esquemas que fallan matemáticamente o pierden preción por el límite de modulo algorítmico.\n")
        print("[*] Evaluando Test 2 - Overflow de Valores Gigantes...")
        for name, engine in engines.items():
            cifrados = [engine.encrypt(g) for g in gastos_grandes]
            suma = engine.sum(cifrados)
            val = engine.decrypt(suma)
            
            if isinstance(val, float):
                # FHE CKKS puede perder algo de precisión
                is_match = abs(val - 6_500_000) < 6_500
            else:
                is_match = val == 6_500_000
                
            f.write(f"[{name}] -> Precisión Mantenida: {'SI' if is_match else 'NO (Sufre Overflow/Error debido a su restricción algorítmica)'}\n")
            
    print(f"\n[OK] ¡Tests completados! Log comparativo exitosamente grabado en: {log_path}")

if __name__ == "__main__":
    run_benchmark()
