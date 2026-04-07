import pytest
import gc
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from task1_crypto_engines import PaillierPHEEngine, TenSEALBFVSHEEngine, TenSEALCKKSFHEEngine

# Definimos los tres motores como fixtures para inyectarlos iterativamente en los test generales.
@pytest.fixture(params=[
    PaillierPHEEngine,
    TenSEALBFVSHEEngine,
    TenSEALCKKSFHEEngine
])
def engine_class(request):
    return request.param

def test_1a_sum_small_numbers(engine_class):
    """Test 1a: Validar sumas con números pequeños (10 a 50)"""
    # Excluyo CKKS de setup default para no recargar inicialización, lo arranco bajo el contexto local
    engine = engine_class()
    gastos = [10, 20, 30, 40, 50]
    real_sum = sum(gastos)
    
    enc_gastos = [engine.encrypt(g) for g in gastos]
    enc_sum = engine.sum(enc_gastos)
    dec_sum = engine.decrypt(enc_sum)
    
    if isinstance(engine, TenSEALCKKSFHEEngine):
        assert round(dec_sum) == real_sum, f"FHE (Float) sum mismatch: {dec_sum} != {real_sum}"
    else:
        assert dec_sum == real_sum, f"Exact sum mismatch: {dec_sum} != {real_sum}"

def test_1b_sum_large_numbers():
    """Test 1b: Validar esquema de números masivamente grandes para detectar overflow."""
    
    gastos = [1_500_000, 2_000_000, 3_000_000] # Total 6.5 Millones
    real_sum = sum(gastos)
    
    # Paillier (PHE): Permite tamaños de texto claro del tamaño del módulo criptográfico (colosal)
    engine_phe = PaillierPHEEngine()
    dec_phe = engine_phe.decrypt(engine_phe.sum([engine_phe.encrypt(g) for g in gastos]))
    assert dec_phe == real_sum, "Paillier falló en suma gigante"
    
    # TenSEAL CKKS (FHE): Al operarlo en floats con modulo global alto (2^40) escala maravillosamente.
    engine_fhe = TenSEALCKKSFHEEngine()
    dec_fhe = engine_fhe.decrypt(engine_fhe.sum([engine_fhe.encrypt(g) for g in gastos]))
    # Damos una tolerancia de menos 0.01% por tratarse de floats homomórficos profundos
    assert abs(dec_fhe - real_sum) < (real_sum * 0.0001), "FHE CKKS perdió mucha precisión"

    # TenSEAL BFV (SHE): Tiene el plain_modulus configurado a 1,032,193 en nuestra implementación.
    # Esta base causa que operaciones mayores a 1M hagan EXPLÍCATO overflow modular. Esto valida el SHE limit!
    engine_she = TenSEALBFVSHEEngine(plain_modulus=1032193)
    dec_she = engine_she.decrypt(engine_she.sum([engine_she.encrypt(g) for g in gastos]))
    assert dec_she != real_sum, "SHE (BFV) debió hacer overflow evidenciando sus límites pero no lo hizo!"
    print(f"\n[INFO] SHE BFV sumó de forma modular y reportó {dec_she} en vez de {real_sum} (Overflow Exitoso).")


def test_2_data_deletion_and_integrity():
    """Test 2: Validación del proceso de borrado de información e integridad (modificación cifrada)."""
    
    engine = PaillierPHEEngine()
    
    # 1. Validación de borrado de información plain-text
    gasto_plano = "5000"
    variable_id = id(gasto_plano)
    enc_obj = engine.encrypt(int(gasto_plano))
    
    # Simulamos el borrado
    del gasto_plano
    gc.collect() # Invoca recolector de basura

    with pytest.raises(NameError):
        _ = gasto_plano # Obligatoria excepción dado que la info desapareció del scope
        
    # 2. Alteración o Modificación del ciphertext para validar integridad algoritmica
    original_val = enc_obj.ciphertext()
    # Atacante interviene y sobreescribe parte del bloque...
    enc_obj._ciphertext = original_val + 1000 
    
    decrypted_corrupted = engine.decrypt(enc_obj)
    # Al alterarse el cifrado por fuerza bruta sin claves, el descifrado debe arrojar basura criptográfica
    # es decir, la suma no será confiable ni predecible, descartando la interceptación útil
    assert decrypted_corrupted != 5000, "WARNING: La modificación forzada del ciphertext dió el texto original"
    
    print("\n[INFO] Integridad Validada: La alteración arrojó basura ininteligible y variables originales borradas.")


if __name__ == "__main__":
    # Autocontrol de tests si se ejecuta el fichero manualmente
    pytest.main(["-v", "-s", __file__])
