# Imagen base recomendada por su ligereza y estabilidad
FROM python:3.11-slim

# Directorio de trabajo
WORKDIR /app

# Instalar dependencias necesarias
# 'phe', 'tenseal', 'pycryptodome' son librerías del ecosistema
RUN pip install --no-cache-dir phe pycryptodome tenseal

# Copiar los directorios de los microservicios
COPY task1/ ./task1/
COPY task2/ ./task2/
COPY task3/ ./task3/

# Usuario no-root para mejorar la seguridad como exige la normativa
RUN useradd -m aerosec
USER aerosec

# Comando por defecto, este ejecutará la simulación de CPIR
CMD ["python", "task3/task3_cpir_vuelos.py"]
