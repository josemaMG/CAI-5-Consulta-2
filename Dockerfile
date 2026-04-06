# Imagen base recomendada por su ligereza y estabilidad
FROM python:3.11-slim

# Directorio de trabajo
WORKDIR /app

# Instalar dependencias necesarias
# 'phe' es la librería para el criptosistema de Paillier
RUN pip install --no-cache-dir phe pycryptodome

# Copiar los scripts de ciberseguridad
COPY task1_homomorphic_sum.py ./
COPY task2_psi_delincuentes.py ./
COPY task3_cpir_vuelos.py ./

# Usuario no-root para mejorar la seguridad como exige la normativa
RUN useradd -m aerosec
USER aerosec

# Comando por defecto, este ejecutará la simulación de CPIR
CMD ["python", "task3_cpir_vuelos.py"]
