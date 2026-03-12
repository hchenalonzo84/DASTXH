# DASTXH (CLI + Docker Desktop, portable)

## Levantar (una sola vez)
docker compose build --no-cache orquestador  
docker compose up -d  
docker compose ps

## Ejecutar scans (Windows CMD)
dastxh.cmd scan https://example.com

## Ejecutar scans (Linux/Mac)
chmod +x dastxh.sh  
./dastxh.sh scan https://example.com  
# o:
make scan URL=https://example.com

## Persistencia
- Postgres: volumen pgdata
- Reportes: volumen workdata en /work/reports/<timestamp>/