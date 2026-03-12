# ==========================================================
# Dockerfile - Orquestador DASTXH (CLI + Tools)
# - Se queda vivo con "sleep infinity" (definido en docker-compose.yml)
# - Ejecutas scans con: docker compose exec orquestador python3 main.py --url ...
# ==========================================================

# ----------------------------------------------------------
# Etapa 1: build de Dalfox (Go)
# - Dalfox v2.12+ requiere Go >= 1.23
# - Usamos bullseye para compatibilidad de GLIBC con el runtime bullseye
# ----------------------------------------------------------
FROM golang:1.23-bullseye AS dalfox_builder
RUN go install github.com/hahwul/dalfox/v2@latest

# ----------------------------------------------------------
# Etapa 2: runtime (Python3 + curl + Python2+hsecscan + dalfox)
# ----------------------------------------------------------
FROM python:3.11-slim-bullseye
ENV DEBIAN_FRONTEND=noninteractive

# 1) Paquetes del sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    tzdata \
    python2 \
    && rm -rf /var/lib/apt/lists/*

# 2) pip2 para Python 2.7 (hsecscan)
RUN curl -fsSL https://bootstrap.pypa.io/pip/2.7/get-pip.py -o /tmp/get-pip.py \
 && python2 /tmp/get-pip.py \
 && rm /tmp/get-pip.py \
 && pip2 --version

# 3) Instalar hsecscan (Python2)
RUN pip2 install --no-cache-dir hsecscan

# 4) Copiar dalfox desde builder
COPY --from=dalfox_builder /go/bin/dalfox /usr/local/bin/dalfox
RUN chmod +x /usr/local/bin/dalfox

# 5) App del orquestador
WORKDIR /app
COPY requirements.txt /app/requirements.txt

# IMPORTANTE: usamos pip de Python3 explícitamente
RUN python3 -m pip install --no-cache-dir -r /app/requirements.txt

COPY app/ /app/app/
WORKDIR /app/app

# No ENTRYPOINT: el compose lo mantiene vivo con sleep infinity