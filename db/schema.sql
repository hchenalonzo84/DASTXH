-- =========================================================
-- DASTXH - Schema mínimo (MVP) + persistencia de capa 2
--
-- Tablas:
--   executions        : historial del run (initiated/finished/failed)
--   header_results    : capa 1 (curl custom)
--   hsecscan_results  : capa 2 (hsecscan) ✅
--   xss_results       : capa 3 (dalfox)
-- =========================================================

CREATE TABLE IF NOT EXISTS executions (
  id              BIGSERIAL PRIMARY KEY,
  target_url      TEXT NOT NULL,
  started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at     TIMESTAMPTZ NULL,
  status          TEXT NOT NULL CHECK (status IN ('initiated','finished','failed')),
  error_message   TEXT NULL,
  urls_ingresadas INT NOT NULL DEFAULT 1 CHECK (urls_ingresadas >= 0),
  urls_evaluadas  INT NOT NULL DEFAULT 0 CHECK (urls_evaluadas >= 0)
);

CREATE INDEX IF NOT EXISTS ix_executions_started_at ON executions (started_at DESC);
CREATE INDEX IF NOT EXISTS ix_executions_status ON executions (status);

-- Capa 1: curl custom
CREATE TABLE IF NOT EXISTS header_results (
  execution_id       BIGINT PRIMARY KEY REFERENCES executions(id) ON DELETE CASCADE,
  headers_evaluadas  INT NOT NULL CHECK (headers_evaluadas >= 0),
  headers_presentes  INT NOT NULL CHECK (headers_presentes >= 0),
  cumplimiento_pct   NUMERIC(6,2) NOT NULL CHECK (cumplimiento_pct >= 0 AND cumplimiento_pct <= 100),
  present_json       JSONB NOT NULL,
  missing_json       JSONB NOT NULL,
  raw_headers_json   JSONB NOT NULL,
  cookies_flags_json JSONB NULL
);

-- Capa 2: hsecscan ✅ (persistimos evidencia para comparar)
CREATE TABLE IF NOT EXISTS hsecscan_results (
  execution_id BIGINT PRIMARY KEY REFERENCES executions(id) ON DELETE CASCADE,
  tool_rc      INT NOT NULL,
  raw_output   TEXT NOT NULL
);

-- Capa 3: Dalfox
CREATE TABLE IF NOT EXISTS xss_results (
  execution_id   BIGINT PRIMARY KEY REFERENCES executions(id) ON DELETE CASCADE,
  findings_count INT NOT NULL CHECK (findings_count >= 0),
  summary_json   JSONB NOT NULL,
  raw_output     TEXT NOT NULL
);