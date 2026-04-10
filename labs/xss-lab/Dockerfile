# ==========================================================
# Dockerfile
# Laboratorio XSS mínimo para pruebas controladas con DASTXH
# ==========================================================

FROM python:3.11-slim-bullseye

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# ----------------------------------------------------------
# Copiar dependencias primero para instalar Flask
# ----------------------------------------------------------
COPY app/requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir -r /app/requirements.txt

# ----------------------------------------------------------
# Copiar el código de la aplicación
# ----------------------------------------------------------
COPY app/ /app/

# ----------------------------------------------------------
# Puerto interno del laboratorio
# ----------------------------------------------------------
EXPOSE 5000

# ----------------------------------------------------------
# Comando de inicio
# ----------------------------------------------------------
CMD ["python", "app.py"]