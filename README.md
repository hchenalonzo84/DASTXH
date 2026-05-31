# DASTXH

DASTXH es un prototipo web para la evaluación dinámica de seguridad en aplicaciones web. Su propósito es integrar en un flujo unificado la verificación de cabeceras HTTP de seguridad, revisión de cookies, análisis de vulnerabilidades de secuencias de comandos entre sitios, generación de evidencia técnica, reportes e interpretación asistida por inteligencia artificial.

El proyecto utiliza Docker Compose para levantar el ecosistema completo, PostgreSQL para almacenar ejecuciones y resultados, Grafana para visualizar indicadores, laboratorios controlados para pruebas reproducibles y Docker Model Runner para ejecutar el modelo de IA local.

---

## Tabla de contenido

* [Características principales](#características-principales)
* [Arquitectura general](#arquitectura-general)
* [Estructura del proyecto](#estructura-del-proyecto)
* [Requisitos previos](#requisitos-previos)
* [Clonar el repositorio](#clonar-el-repositorio)
* [Configuración del entorno](#configuración-del-entorno)
* [Configuración de Docker Model Runner](#configuración-de-docker-model-runner)
* [Ejecución con Docker Compose](#ejecución-con-docker-compose)
* [Acceso a los servicios](#acceso-a-los-servicios)
* [Uso general](#uso-general)
* [Laboratorios incluidos](#laboratorios-incluidos)
* [Grafana e indicadores](#grafana-e-indicadores)
* [Comandos útiles](#comandos-útiles)
* [Solución de problemas frecuentes](#solución-de-problemas-frecuentes)
* [Uso autorizado](#uso-autorizado)

---

## Características principales

* Interfaz web para iniciar evaluaciones.
* API documentada mediante Swagger.
* Historial de ejecuciones almacenado en PostgreSQL.
* Verificación de cabeceras HTTP de seguridad.
* Revisión de cookies observadas en la respuesta.
* Integración con hsecscan como herramienta complementaria.
* Integración con Dalfox para análisis XSS.
* Verificación headless mediante Chromium.
* Interpretación asistida por IA para resultados técnicos.
* Generación de archivos de evidencia por ejecución.
* Reporte general consultable desde la interfaz.
* Dashboards de indicadores en Grafana.
* Laboratorios controlados desplegados con Docker Compose.

---

## Arquitectura general

El ecosistema de DASTXH se compone de varios servicios coordinados mediante Docker Compose.

| Componente          | Descripción                                                                                                     |
| ------------------- | --------------------------------------------------------------------------------------------------------------- |
| Orquestador         | Aplicación principal basada en FastAPI. Expone la GUI, API, historial, ejecución de evaluaciones y reportes.    |
| PostgreSQL          | Base de datos relacional donde se almacenan ejecuciones, resultados, artifacts, reportes e interpretaciones IA. |
| Grafana             | Herramienta de visualización conectada directamente a PostgreSQL para mostrar indicadores del prototipo.        |
| Laboratorios        | Escenarios web controlados para validar cabeceras, cookies y XSS.                                               |
| Docker Model Runner | Motor local para ejecutar el modelo de IA utilizado por el prototipo.                                           |
| Dalfox              | Herramienta integrada para evaluación de XSS.                                                                   |
| hsecscan            | Herramienta complementaria para revisión de configuraciones de seguridad web.                                   |
| Chromium            | Navegador headless utilizado para validaciones basadas en navegador.                                            |

---

## Estructura del proyecto

```text
DASTXH/
├── db/
│   └── schema.sql
│
├── grafana/
│   ├── dashboards/
│   │   └── dastxh-kpis-dashboard.json
│   └── provisioning/
│
├── labs/
│   ├── combo-lab/
│   │   ├── app/
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   │
│   └── scenario-labs/
│       ├── app.py
│       ├── Dockerfile
│       └── requirements.txt
│
├── orquestador/
│   ├── app/
│   │   ├── api/
│   │   ├── repositories/
│   │   ├── services/
│   │   ├── tools/
│   │   ├── web/
│   │   │   ├── static/
│   │   │   └── templates/
│   │   ├── config.py
│   │   ├── db.py
│   │   ├── main.py
│   │   ├── report.py
│   │   └── webapp.py
│   │
│   ├── Dockerfile
│   └── requirements.txt
│
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md
```

---

## Requisitos previos

Antes de ejecutar el proyecto se requiere tener instalado:

* Git.
* Docker Desktop o Docker Engine.
* Docker Compose.
* Docker Model Runner.
* Navegador web actualizado.

En Windows se recomienda utilizar Docker Desktop. En Linux se puede utilizar Docker Engine con el plugin de Docker Model Runner.

---

## Clonar el repositorio

```bash
git clone <URL_DEL_REPOSITORIO>
cd <NOMBRE_DEL_REPOSITORIO>
```

Ejemplo:

```bash
git clone https://github.com/usuario/dastxh.git
cd dastxh
```

---

## Configuración del entorno

El proyecto utiliza variables de entorno. Antes de levantar los contenedores se debe crear un archivo `.env` a partir de `.env.example`.

### Linux, macOS o Git Bash

```bash
cp .env.example .env
```

### PowerShell

```powershell
Copy-Item .env.example .env
```

Luego se debe revisar el archivo `.env` y ajustar los valores según el entorno local.

Ejemplo de configuración orientativa:

```env
# ==========================================================
# PostgreSQL
# ==========================================================
POSTGRES_DB=dastxh
POSTGRES_USER=dastxh
POSTGRES_PASSWORD=dastxh_password
POSTGRES_HOST=db
POSTGRES_PORT=5432

# ==========================================================
# Orquestador
# ==========================================================
DASTXH_DEFAULT_TIMEOUT=30
DASTXH_WORKDIR=/work
DASTXH_REPORTS_DIR=/work/reports

# ==========================================================
# Dalfox
# ==========================================================
DASTXH_DALFOX_REQUEST_TIMEOUT_SECONDS=25
DASTXH_DALFOX_HARD_TIMEOUT_SECONDS=420
DASTXH_DALFOX_WORKERS=6
DASTXH_DALFOX_LIGHT_MINING_ENABLED=true
DASTXH_DALFOX_SKIP_MINING_DOM=false
DASTXH_DALFOX_SKIP_MINING_DICT=false
DASTXH_DALFOX_DEEP_DOMXSS_ENABLED=true
DASTXH_DALFOX_FORCE_HEADLESS_VERIFICATION=true

# ==========================================================
# Inteligencia artificial local
# ==========================================================
DASTXH_AI_ENABLED=true
DASTXH_AI_PROVIDER=docker-model-runner
DASTXH_AI_MODEL=ai/llama3.2
DASTXH_AI_BASE_URL=http://model-runner.docker.internal:12434/engines/v1
DASTXH_AI_API_KEY=not-needed

# ==========================================================
# Grafana
# ==========================================================
GRAFANA_PORT=3000
```

Los nombres exactos de las variables deben coincidir con el archivo `.env.example` incluido en el repositorio.

---

## Configuración de Docker Model Runner

DASTXH puede utilizar Docker Model Runner para ejecutar localmente el modelo de IA encargado de interpretar hallazgos técnicos.

### 1. Habilitar Docker Model Runner en Docker Desktop

Desde Docker Desktop:

1. Abrir **Settings**.
2. Ir a la sección **AI**.
3. Activar **Enable Docker Model Runner**.
4. Activar **Enable host-side TCP support**.
5. Usar el puerto `12434`.
6. Si se utiliza Windows con GPU NVIDIA compatible, activar **Enable GPU-backed inference**.

También puede habilitarse desde CLI:

```bash
docker desktop enable model-runner --tcp 12434
```

### 2. Verificar instalación

```bash
docker model version
```

### 3. Descargar el modelo

```bash
docker model pull ai/llama3.2
```

### 4. Probar el modelo desde terminal

```bash
docker model run ai/llama3.2
```

### 5. Ver modelos descargados

```bash
docker model list
```

### 6. Probar el endpoint TCP desde el host

```bash
curl http://localhost:12434/engines/v1/models
```

### 7. Acceso desde contenedores

Para que el orquestador pueda comunicarse con Docker Model Runner, el servicio puede requerir una configuración como esta en `docker-compose.yml`:

```yaml
extra_hosts:
  - "model-runner.docker.internal:host-gateway"
```

El endpoint usado por el backend queda configurado como:

```text
http://model-runner.docker.internal:12434/engines/v1
```

---

## Ejecución con Docker Compose

### Construir los servicios

```bash
docker compose build
```

### Levantar el ecosistema

```bash
docker compose up -d
```

### Ver contenedores activos

```bash
docker compose ps
```

### Detener los servicios

```bash
docker compose down
```

### Detener servicios y limpiar contenedores huérfanos

```bash
docker compose down --remove-orphans
```

### Reconstruir sin caché

```bash
COMPOSE_PARALLEL_LIMIT=1 docker compose build --no-cache
docker compose up -d
```

En PowerShell:

```powershell
$env:COMPOSE_PARALLEL_LIMIT=1
docker compose build --no-cache
docker compose up -d
```

### Reconstruir solo el orquestador

```bash
COMPOSE_PARALLEL_LIMIT=1 docker compose build --no-cache orquestador
docker compose up -d
```

### Reiniciar el orquestador

```bash
docker compose restart orquestador
```

### Reiniciar Grafana

```bash
docker compose restart grafana
```

---

## Acceso a los servicios

Cuando los contenedores estén levantados, se puede acceder a:

| Servicio                 | URL                                               |
| ------------------------ | ------------------------------------------------- |
| Interfaz web DASTXH      | `http://localhost:8000`                           |
| API Docs                 | `http://localhost:8000/docs`                      |
| Historial                | `http://localhost:8000/history`                   |
| Grafana                  | `http://localhost:3000`                           |
| Laboratorios controlados | `http://localhost:5101` a `http://localhost:5110` |

---

## Uso general

1. Abrir la interfaz web en `http://localhost:8000`.
2. Ingresar una URL objetivo autorizada.
3. Ejecutar la evaluación.
4. Consultar el estado desde el historial.
5. Abrir el detalle de la ejecución.
6. Revisar el resumen, detalle técnico, artifacts y reporte general.
7. Consultar los indicadores desde Grafana.

El menú superior de la aplicación incluye accesos a:

* Inicio.
* Historial.
* API Docs.
* Laboratorios.
* Grafana.

---

## Laboratorios incluidos

El proyecto incluye laboratorios controlados desplegados con Docker Compose. Estos escenarios permiten validar el comportamiento del prototipo en condiciones reproducibles.

Los laboratorios cubren escenarios como:

* Cabeceras de seguridad presentes.
* Cabeceras de seguridad faltantes.
* Política CSP débil.
* Cookies inseguras.
* XSS básico.
* XSS parcialmente filtrado.
* Sitios sin XSS para contraste.
* Escenarios mixtos con buenas y malas prácticas.

Los laboratorios se exponen en puertos locales:

```text
http://localhost:5101
http://localhost:5102
http://localhost:5103
http://localhost:5104
http://localhost:5105
http://localhost:5106
http://localhost:5107
http://localhost:5108
http://localhost:5109
http://localhost:5110
```

Desde el contenedor orquestador también pueden ser alcanzados mediante nombres de servicio Docker definidos en `docker-compose.yml`.

---

## Evaluación de servicios locales del host

DASTXH permite evaluar servicios locales levantados fuera de Docker, por ejemplo aplicaciones ejecutadas con XAMPP, Nginx local, Live Server u otro servidor de desarrollo.

Ejemplos de URLs ingresadas por el usuario:

```text
http://localhost/sitioVM/index.html?mensaje=hola
http://127.0.0.1:5500/index.html?mensaje=hola
```

Dentro del contenedor, estas URLs se normalizan hacia:

```text
host.docker.internal
```

Esto permite que el orquestador pueda alcanzar servicios del equipo host desde el entorno Docker. En la interfaz se muestran etiquetas visuales para diferenciar entre:

* Laboratorio Docker DASTXH.
* Servicio local del equipo host.
* Objetivo externo autorizado.

---

## Grafana e indicadores

Grafana se utiliza como capa de observabilidad del prototipo. El dashboard se conecta directamente a PostgreSQL y consulta los datos almacenados por DASTXH.

El tablero principal incluye:

* Resumen general de evaluaciones.
* Indicador 1: eficiencia operativa de la evaluación.
* Indicador 2: tasa de detección XSS en escenarios vulnerables.
* Indicador 3: cumplimiento promedio de cabeceras de seguridad.
* Indicador 4: cobertura de interpretación asistida por IA.
* Evidencia complementaria de ejecuciones recientes.

Indicadores principales:

| Indicador                          | Fórmula                                                                                           |
| ---------------------------------- | ------------------------------------------------------------------------------------------------- |
| Duración promedio por evaluación   | suma de duraciones de evaluaciones finalizadas / total de evaluaciones finalizadas                |
| Tasa de detección XSS              | evaluaciones vulnerables con hallazgos XSS detectados / evaluaciones vulnerables ejecutadas × 100 |
| Cumplimiento promedio de cabeceras | promedio del cumplimiento obtenido en evaluaciones finalizadas                                    |
| Interpretación IA exitosa          | elementos con interpretación IA generada / elementos que requerían interpretación IA × 100        |

---

## Artifacts y reportes

Cada evaluación genera evidencia técnica en una carpeta independiente dentro del volumen de trabajo del orquestador.

Ejemplo:

```text
/work/reports/20260530_194738
```

Archivos que pueden generarse por ejecución:

```text
run_meta.json
headers.json
hsecscan.txt
dalfox.json
dalfox.txt
report.md
report.html
report.pdf
```

Estos archivos permiten consultar evidencia técnica y respaldar los resultados mostrados en la interfaz web.

---

## Comandos útiles

### Ver logs del orquestador

```bash
docker compose logs -f orquestador
```

### Ver logs de Grafana

```bash
docker compose logs -f grafana
```

### Ver logs de PostgreSQL

```bash
docker compose logs -f db
```

### Entrar al contenedor del orquestador

```bash
docker compose exec orquestador sh
```

### Ver procesos de herramientas internas

```bash
docker compose exec orquestador sh -lc 'ps -ef | grep -E "dalfox|hsecscan|chromium" | grep -v grep'
```

### Ver carpetas de reportes

```bash
docker compose exec orquestador sh -lc 'ls -lah /work/reports'
```

### Ver últimos archivos generados

```bash
docker compose exec orquestador sh -lc 'find /work/reports -maxdepth 2 -type f | tail -n 30'
```

### Ver salida reciente de Dalfox

```bash
docker compose exec orquestador sh -lc 'find /work/reports -name dalfox.txt -type f | tail -n 1 | xargs cat | head -n 40'
```

### Ver variables de entorno de Dalfox dentro del contenedor

```bash
docker compose exec orquestador printenv | grep DASTXH_DALFOX
```

### Ver modelos disponibles

```bash
docker model list
```

### Probar Docker Model Runner desde el host

```bash
curl http://localhost:12434/engines/v1/models
```

---

## Solución de problemas frecuentes

### Docker Model Runner no responde

Verificar que Docker Model Runner esté habilitado y que el soporte TCP esté activo.

```bash
docker model version
docker model list
curl http://localhost:12434/engines/v1/models
```

Si se usa Docker Desktop, revisar:

```text
Settings > AI > Enable Docker Model Runner
Settings > AI > Enable host-side TCP support
Port: 12434
```

También puede habilitarse con:

```bash
docker desktop enable model-runner --tcp 12434
```

---

### El orquestador no puede conectarse al modelo IA

Verificar en `.env`:

```env
DASTXH_AI_BASE_URL=http://model-runner.docker.internal:12434/engines/v1
```

Verificar en `docker-compose.yml` que el servicio del orquestador pueda resolver el host:

```yaml
extra_hosts:
  - "model-runner.docker.internal:host-gateway"
```

---

### Grafana no muestra cambios del dashboard

Reiniciar Grafana:

```bash
docker compose restart grafana
```

Si el cambio no se refleja:

```bash
docker compose down --remove-orphans
COMPOSE_PARALLEL_LIMIT=1 docker compose build --no-cache grafana
docker compose up -d
```

---

### El orquestador no alcanza una URL local

Si se evalúa un servicio local del equipo host, verificar que el servicio esté levantado y accesible desde el navegador.

Ejemplo:

```text
http://localhost/sitioVM/index.html
```

DASTXH normaliza internamente estas URLs hacia `host.docker.internal` para que sean accesibles desde el contenedor.

---

### hsecscan falla contra un servidor local

Algunos servidores de desarrollo pueden comportarse distinto frente a herramientas automatizadas. Para pruebas más estables se recomienda utilizar laboratorios Docker, XAMPP o Nginx local.

---

### Docker falla descargando imágenes

Si Docker Desktop falla durante descargas o builds, revisar conexión de red, DNS, proxy, firewall o configuración IPv6 del adaptador de red.

---

## Uso autorizado

DASTXH debe utilizarse únicamente en:

* Laboratorios incluidos en el proyecto.
* Aplicaciones propias.
* Entornos locales de desarrollo.
* Sistemas donde exista autorización explícita para realizar evaluaciones.

No se recomienda ejecutar el prototipo contra servicios de terceros sin permiso. Algunas herramientas integradas generan tráfico automatizado y pueden activar bloqueos, restricciones o mecanismos de defensa en sitios externos.

---

## Licencia

Definir la licencia antes de publicar el repositorio.

Ejemplo:

```text
MIT License
```

---

## Autor

Proyecto desarrollado con fines académicos como prototipo de evaluación dinámica de seguridad web asistida por inteligencia artificial.
