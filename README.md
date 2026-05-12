# DASTXH

DASTXH es un prototipo académico de evaluación dinámica de seguridad web orientado a pruebas de caja negra sobre URLs autorizadas.

El proyecto integra actualmente dos líneas principales de evaluación:

1. **Revisión HTTP**
   - cabeceras HTTP de seguridad
   - atributos de cookies
   - prueba básica complementaria de CORS

2. **Análisis XSS con Dalfox**
   - enfocado principalmente en **XSS reflejado**
   - pensado para URLs con parámetros funcionales

Además, el proyecto ya incorpora una etapa interna para:

- agrupar hallazgos XSS similares
- preparar esos grupos para interpretación más humana
- permitir una integración opcional con IA local mediante un backend compatible con OpenAI

---

## Estado actual del proyecto

Actualmente DASTXH incluye:

- **GUI web** con FastAPI + Jinja2
- **PostgreSQL** para historial y persistencia
- **pgAdmin** para revisión manual de la base de datos
- **Docker Compose** para orquestación portable
- **Laboratorio combinado** con su propia base de datos para pruebas controladas
- **Integración opcional con IA local** para interpretar grupos XSS de forma más entendible

---

## Alcance funcional actual

### Revisión HTTP

DASTXH evalúa actualmente:

#### Grupo A: cabeceras principales
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`

#### Grupo B: aislamiento / cross-origin
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy`
- `Cross-Origin-Resource-Policy`
- `Cross-Origin-Embedder-Policy`
- prueba básica de **CORS**

#### Grupo C: cookies
- atributo `Secure`
- atributo `HttpOnly`
- atributo `SameSite`

### Revisión XSS

DASTXH usa **Dalfox** para evaluar superficies adecuadas para **XSS reflejado**.

La herramienta funciona mejor cuando la URL objetivo contiene parámetros reales de negocio, por ejemplo:

- búsqueda
- filtros
- paginación
- ordenamientos
- IDs
- query strings útiles

Ejemplos adecuados:

- `https://sitio.com/search?q=arduino`
- `https://sitio.com/index.php?route=product/search&search=arduino&description=true`

Ejemplos menos útiles para Dalfox:

- páginas estáticas sin parámetros
- rutas de inicio sin query string
- parámetros de tracking que no intervienen realmente en la lógica del sitio

---

## Estructura general del proyecto

```text
dastxh/
├─ .env
├─ .env.example
├─ .gitignore
├─ docker-compose.yml
├─ README.md
├─ db/
│  └─ schema.sql
├─ orquestador/
│  ├─ Dockerfile
│  └─ app/
│     ├─ api/
│     ├─ services/
│     ├─ tools/
│     ├─ web/
│     │  ├─ static/
│     │  └─ templates/
│     ├─ config.py
│     ├─ db.py
│     ├─ main.py
│     ├─ report.py
│     ├─ utils.py
│     └─ webapp.py
├─ workdata/
│  └─ reports/
└─ labs/
   └─ combo-lab/
      ├─ app/
      ├─ db/
      └─ Dockerfile
      
## Comandos principales del proyecto
1. Preparar Docker Model Runner
docker desktop enable model-runner --tcp=12434
docker model pull ai/llama3.2
docker model configure --context-size 2048 ai/llama3.2
curl http://localhost:12434/v1/models
2. Levantar DASTXH completo
docker compose down -v
docker compose build --no-cache
docker compose up -d
docker compose ps
3. Ver logs si algo falla
docker compose logs -f orquestador
docker compose logs -f combo-lab
docker compose logs -f db
4. Bajar el stack
docker compose down
5. Bajar el stack borrando volúmenes
docker compose down -v
URLs que usarás
GUI DASTXH: http://localhost:8000
pgAdmin: http://localhost:5050
Combo Lab: http://localhost:5003
URL de prueba inicial en la GUI
http://combo-lab:5000/search?q=phone
Perfil recomendado para la primera prueba
superficial
Uso básico desde la GUI
Abrir la GUI:
http://localhost:8000
Introducir una URL objetivo.
Elegir perfil:
superficial
profundo
Ejecutar evaluación.
Reportes y artifacts

Los reportes se almacenan en:

workdata/reports/<run_id>/

Normalmente ahí se generan archivos como:

report.md
report.html
headers.json
dalfox.json
dalfox.txt
run_meta.json

Y si el perfil es profundo, también puede aparecer:

hsecscan.txt

docker compose down -v
docker compose build --no-cache
docker compose up -d
docker compose ps