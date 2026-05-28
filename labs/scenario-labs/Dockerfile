# ==========================================================
# labs/scenario-labs/Dockerfile
# DASTXH - Laboratorios de escenarios controlados
#
# Objetivo:
# - Construir una imagen reutilizable para varios laboratorios.
# - Cada laboratorio cambia su comportamiento mediante LAB_SCENARIO.
#
# Importante:
# - Estos laboratorios son educativos y controlados.
# - No deben exponerse públicamente en internet.
# ==========================================================

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

WORKDIR /app

# Copiamos el archivo de dependencias con un nombre alternativo
# porque en tu entorno requirements.txt no fue aceptado.
COPY dependencies.txt /app/dependencies.txt

# Instalamos las dependencias necesarias para Flask y Gunicorn.
RUN pip install --no-cache-dir -r /app/dependencies.txt

# Copiamos la aplicación principal del laboratorio.
COPY app.py /app/app.py

EXPOSE 5000

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} app:app"]