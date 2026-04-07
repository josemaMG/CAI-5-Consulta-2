import sys
import os
import random
from phe import paillier
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from task3_cpir_vuelos import buscaVuelo
import datetime

def manual_test():
    log_content = "=========================================================================\n"
    log_content += " REPORTE DE EFICACIA Y RENDIMIENTO: PROTOCOLO CPIR PARA VUELOS (Tarea 3)\n"
    log_content += "=========================================================================\n\n"
    log_content += f"Fecha de ejecución: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    log_content += "Objetivo: Validar los tiempos de latencia y nivel de privacidad del cliente sobre un modelo Paillier.\n\n"
    
    test_cases = [
        {"vuelos_bd": 300, "vuelo_buscar": 150},
        {"vuelos_bd": 800, "vuelo_buscar": 404},
        {"vuelos_bd": 1273, "vuelo_buscar": 1200}
    ]
    
    print("Generando claves criptográficas de 2048 bits para tests. Esto puede tomar unos segundos...")
    public_key, private_key = paillier.generate_paillier_keypair(n_length=2048)

    for idx, case in enumerate(test_cases, 1):
        n_vuelos = case["vuelos_bd"]
        id_buscar = case["vuelo_buscar"]
        
        precios = [random.randint(50, 1500) for _ in range(n_vuelos)]
        precio_real = precios[id_buscar]
        
        precio_cpir, t_ejecucion = buscaVuelo(id_buscar, n_vuelos, public_key, private_key, precios)
        
        log_content += f"--- TEST {idx}: LATENCIA ESCALABLE (Base de datos: {n_vuelos} Vuelos) ---\n"
        log_content += f"  - Vuelo ID Consultado: {id_buscar}\n"
        log_content += f"  - Tiempo total operación (Cliente + Servidor): {t_ejecucion:.4f} segundos\n"
        log_content += f"  - Precio Real de la BD: {precio_real} EUR\n"
        log_content += f"  - Precio Recuperado Vía CPIR: {precio_cpir} EUR\n"
        log_content += f"  - Eficacia y Precisión Comprobada: {'SI' if precio_real == precio_cpir else 'NO'}\n\n"
    
    with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "task3_cpir_resultados.log"), "w", encoding="utf-8") as f:
        f.write(log_content)
    
    print("Log generado en logs/task3_cpir_resultados.log")

if __name__ == "__main__":
    manual_test()
