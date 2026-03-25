# DASTXH

Prototipo académico de evaluación DAST de caja negra orientado a sitios web.

Actualmente integra tres capas principales de análisis:

1. **Capa 1:** evaluación custom de cabeceras HTTP de seguridad con `curl`
2. **Capa 2:** análisis complementario de hardening con `hsecscan`
3. **Capa 3:** detección de posibles hallazgos XSS con `Dalfox`

El proyecto funciona con:

- **CLI**
- **GUI web** con FastAPI + Jinja2
- **PostgreSQL** para historial y persistencia
- **pgAdmin** para revisión manual de la base de datos
- **Docker Compose** para orquestación portable

---

## Estructura general

- `db/`
  - `schema.sql`
- `orquestador/`
  - `app/`
    - `api/`
    - `services/`
    - `tools/`
    - `web/`
    - `config.py`
    - `db.py`
    - `main.py`
    - `report.py`
    - `utils.py`
    - `webapp.py`
- `workdata/`
  - `reports/`
- `.env`
- `.env.example`
- `.gitignore`
- `docker-compose.yml`

---

## Levantar el stack

```bash
docker compose build --no-cache
docker compose up -d
docker compose ps

---

## Levantar el stack
docker compose exec orquestador python3 main.py --url 
