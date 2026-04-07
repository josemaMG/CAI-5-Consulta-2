import tenseal as ts
from phe import paillier

class CryptoEngine:
    def encrypt(self, number):
        raise NotImplementedError
        
    def decrypt(self, encrypted_obj):
        raise NotImplementedError
        
    def sum(self, encrypted_list):
        raise NotImplementedError

class PaillierPHEEngine(CryptoEngine):
    """
    Partial Homomorphic Encryption (PHE) orientada a sumas exactas infinitas.
    Usa criptosistema de Paillier de la librería 'phe'.
    """
    def __init__(self, key_size=1024):
        self.public_key, self.private_key = paillier.generate_paillier_keypair(n_length=key_size)
        
    def encrypt(self, number):
        return self.public_key.encrypt(number)
        
    def decrypt(self, encrypted_obj):
        return self.private_key.decrypt(encrypted_obj)
        
    def sum(self, encrypted_list):
        if not encrypted_list:
            return 0
        return sum(encrypted_list)


class TenSEALBFVSHEEngine(CryptoEngine):
    """
    Somewhat Homomorphic Encryption (SHE)
    Esquema Brakerski/Fan-Vercauteren (BFV) implementado en TenSEAL.
    Maneja aritmética exacta de enteros. Sensible a OVERFLOW si plain_modulus es rebasado.
    """
    def __init__(self, plain_modulus=1032193):
        # Configuramos BFV sin bootstrapping, operando puramente como SHE
        self.context = ts.context(
            ts.SCHEME_TYPE.BFV,
            poly_modulus_degree=8192,
            plain_modulus=plain_modulus
        )
        self.context.generate_galois_keys()
        self.context.generate_relin_keys()

    def encrypt(self, number):
        # BFV de TenSEAL serializa vectores enteros
        return ts.bfv_vector(self.context, [int(number)])
        
    def decrypt(self, encrypted_obj):
        res = encrypted_obj.decrypt()
        return res[0]
        
    def sum(self, encrypted_list):
        if not encrypted_list:
            return None
        # En TenSEAL la sobrecarga de operadores suma los cifrados
        res = encrypted_list[0]
        for e in encrypted_list[1:]:
            res = res + e
        return res


class TenSEALCKKSFHEEngine(CryptoEngine):
    """
    Fully Homomorphic Encryption (FHE) (Enfoque Leveled / Float point)
    Esquema Cheon-Kim-Kim-Song (CKKS) implementado en TenSEAL.
    Ideal para matemáticas con decimales y redes neuronales, aproximado.
    """
    def __init__(self):
        # CKKS requiere la asignación de bits para los coeficientes modulares y la escala global
        self.context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=8192,
            coeff_mod_bit_sizes=[60, 40, 40, 60]
        )
        self.context.global_scale = 2**40
        self.context.generate_galois_keys()
        self.context.generate_relin_keys()

    def encrypt(self, number):
        return ts.ckks_vector(self.context, [float(number)])
        
    def decrypt(self, encrypted_obj):
        res = encrypted_obj.decrypt()
        return res[0] # Al ser aproximado, devuelve un float que podría no ser la representación exacta
        
    def sum(self, encrypted_list):
        if not encrypted_list:
            return None
        res = encrypted_list[0]
        for e in encrypted_list[1:]:
            res = res + e
        return res
