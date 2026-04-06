import time
import random
from phe import paillier

def simulate_homomorphic_sum(num_clientes=50, n_length=1024):
    """ Función testeable para la suma homomórfica """
    public_key, private_key = paillier.generate_paillier_keypair(n_length=n_length)
    gastos = [random.randint(10, 50000) for _ in range(num_clientes)]
    gasto_total_real = sum(gastos)
    
    # Cifrado
    encrypted_gastos = [public_key.encrypt(g) for g in gastos]
    
    # Suma en la nube
    encrypted_sum = sum(encrypted_gastos)
    
    # Descifrado
    decrypted_sum = private_key.decrypt(encrypted_sum)
    return gasto_total_real, decrypted_sum

def main():
    print("--- TAREA 2.1: Privacidad en Suma de Gastos de Clientes en Nube Pública ---")
    
    # Generar claves del cliente (tamaño de clave recomendado de 2048)
    print("Generando claves criptográficas de Paillier de 2048 bits...")
    start_time = time.time()
    public_key, private_key = paillier.generate_paillier_keypair(n_length=2048)
    end_time = time.time()
    key_gen_time = end_time - start_time
    print(f"Tiempo de generación de claves: {key_gen_time:.4f} segundos.")

    # Simular una cantidad de gastos aleatoria entre números pequeños y grandes
    num_clientes = 50
    gastos = [random.randint(10, 50000) for _ in range(num_clientes)]
    gasto_total_real = sum(gastos)
    
    # 1. El cliente (aerolínea) cifra cada gasto individualmente antes de enviarlo a la nube
    print(f"\nCifrando {num_clientes} registros de gastos en el cliente...")
    start_time = time.time()
    encrypted_gastos = [public_key.encrypt(g) for g in gastos]
    end_time = time.time()
    enc_time = end_time - start_time
    print(f"Tiempo total de cifrado de {num_clientes} gastos: {enc_time:.4f} segundos.")
    print(f"Tiempo promedio de cifrado por dato: {enc_time/num_clientes:.4f} segundos.")

    # 2. La nube recibe los datos cifrados y los procesa (los suma homomórficamente)
    # Ningún dato es descifrado en este paso.
    print("\nProcesando suma homomórfica en la Nube Pública...")
    start_time = time.time()
    
    # Se suman todos los objetos encriptados. El criptosistema Paillier permite: E(m1) + E(m2) = E(m1 + m2)
    encrypted_sum = sum(encrypted_gastos)
    
    end_time = time.time()
    sum_time = end_time - start_time
    
    # Comparación de eficiencia (nube vs cliente sin cifrar)
    start_time_clear = time.time()
    sum(gastos)
    end_time_clear = time.time()
    sum_time_clear = end_time_clear - start_time_clear
    
    print(f"Tiempo de suma homomórfica: {sum_time:.4f} segundos.")
    print(f"Tiempo de suma convencional en texto claro: {sum_time_clear:.6f} segundos.")

    # 3. La nube devuelve la suma cifrada al cliente, quien la descifra
    print("\nDescifrando el resultado de la nube en el entorno de la Aerolínea...")
    start_time = time.time()
    decrypted_sum = private_key.decrypt(encrypted_sum)
    end_time = time.time()
    dec_time = end_time - start_time
    print(f"Tiempo de descifrado del resultado total: {dec_time:.4f} segundos.")

    # 4. Verificación de eficacia
    print("\n--- Resultados de Pruebas de Eficacia ---")
    print(f"Gasto Total Real (texto claro): {gasto_total_real}")
    print(f"Gasto Total Calculado en la Nube (descifrado): {decrypted_sum}")
    if gasto_total_real == decrypted_sum:
        print("EFICACIA COMPROBADA: El cifrado homomórfico preservó la integridad de la suma al 100%.")
    else:
        print("ERROR: La suma obtenida NO es igual a la suma real.")

if __name__ == "__main__":
    main()
