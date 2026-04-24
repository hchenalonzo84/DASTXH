# ==========================================================
# Dockerfile
# Laboratorio combinado tipo tienda online para pruebas con DASTXH
# ==========================================================

FROM python:3.11-slim-bullseye

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# ----------------------------------------------------------
# Instalar dependencias Python del laboratorio
# ----------------------------------------------------------
COPY app/requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir -r /app/requirements.txt

# ----------------------------------------------------------
# Copiar la aplicación del laboratorio
# ----------------------------------------------------------
COPY app/ /app/

# ----------------------------------------------------------
# Puerto interno del laboratorio
# ----------------------------------------------------------
EXPOSE 5000

# ----------------------------------------------------------
# Comando de arranque
# ----------------------------------------------------------
CMD ["python", "app.py"]