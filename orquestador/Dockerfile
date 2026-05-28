# ==========================================================
# Dockerfile - Orquestador DASTXH
# - Soporta CLI + GUI web (FastAPI)
# - Incluye curl + hsecscan + dalfox
# - Incluye Chromium para verificación headless / DOM XSS
# ==========================================================

# ----------------------------------------------------------
# Etapa 1: build de Dalfox (Go)
# ----------------------------------------------------------
FROM golang:1.23-bullseye AS dalfox_builder

# Instala Dalfox desde el repositorio oficial.
# Esta herramienta se usará para la capa de evaluación XSS.
RUN go install github.com/hahwul/dalfox/v2@v2.12.0


# ----------------------------------------------------------
# Etapa 2: runtime principal
# ----------------------------------------------------------
FROM python:3.11-slim-bullseye

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ----------------------------------------------------------
# Variables para Chromium / Headless
# ----------------------------------------------------------
# Estas variables ayudan a que herramientas que necesitan un navegador
# puedan localizar Chromium dentro del contenedor.
#
# Importante:
# Esto solo prepara el contenedor. La activación real de:
#   --deep-domxss
#   --force-headless-verification
# se hace en el código que arma el comando de Dalfox.
# ----------------------------------------------------------
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMIUM_BIN=/usr/bin/chromium

# ----------------------------------------------------------
# Paquetes del sistema
# ----------------------------------------------------------
# Se instala:
# - curl: usado por el prototipo y utilidades HTTP.
# - python2: requerido por hsecscan.
# - chromium: navegador headless para verificación DOM/XSS.
# - librerías auxiliares: necesarias para que Chromium funcione bien
#   dentro de contenedores Linux sin interfaz gráfica.
# ----------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    tzdata \
    python2 \
    chromium \
    fonts-liberation \
    libnss3 \
    libgbm1 \
    libasound2 \
    libxss1 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

# ----------------------------------------------------------
# pip para Python 2 (requerido por hsecscan)
# ----------------------------------------------------------
RUN curl -fsSL https://bootstrap.pypa.io/pip/2.7/get-pip.py -o /tmp/get-pip.py \
 && python2 /tmp/get-pip.py \
 && rm /tmp/get-pip.py \
 && pip2 --version

# ----------------------------------------------------------
# Instalar hsecscan
# ----------------------------------------------------------
RUN pip2 install --no-cache-dir hsecscan

# ----------------------------------------------------------
# Copiar Dalfox desde la etapa builder
# ----------------------------------------------------------
COPY --from=dalfox_builder /go/bin/dalfox /usr/local/bin/dalfox

RUN chmod +x /usr/local/bin/dalfox

# ----------------------------------------------------------
# Verificaciones básicas de herramientas instaladas
# ----------------------------------------------------------
# Estas verificaciones ayudan a detectar errores durante el build.
# Si alguna herramienta no quedó disponible, el build fallará aquí.
# ----------------------------------------------------------
RUN dalfox version \
 && chromium --version \
 && curl --version

# ----------------------------------------------------------
# App Python
# ----------------------------------------------------------
WORKDIR /app

# Primero se copian dependencias para aprovechar mejor la caché de Docker.
COPY requirements.txt /app/requirements.txt

RUN python3 -m pip install --no-cache-dir -r /app/requirements.txt

# Copiar aplicación completa
COPY app/ /app/app/

# Directorio de trabajo final
WORKDIR /app/app

# Puerto de la GUI web
EXPOSE 8000

# El comando real lo definirá docker-compose
CMD ["sleep", "infinity"]