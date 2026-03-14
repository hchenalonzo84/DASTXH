# ==========================================================
# Dockerfile - Orquestador DASTXH
# - Soporta CLI + GUI web (FastAPI)
# - Incluye curl + hsecscan + dalfox
# ==========================================================

# ----------------------------------------------------------
# Etapa 1: build de Dalfox (Go)
# ----------------------------------------------------------
FROM golang:1.23-bullseye AS dalfox_builder
RUN go install github.com/hahwul/dalfox/v2@latest

# ----------------------------------------------------------
# Etapa 2: runtime principal
# ----------------------------------------------------------
FROM python:3.11-slim-bullseye

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ----------------------------------------------------------
# Paquetes del sistema
# ----------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    tzdata \
    python2 \
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
# Copiar dalfox desde builder
# ----------------------------------------------------------
COPY --from=dalfox_builder /go/bin/dalfox /usr/local/bin/dalfox
RUN chmod +x /usr/local/bin/dalfox

# ----------------------------------------------------------
# App Python
# ----------------------------------------------------------
WORKDIR /app
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