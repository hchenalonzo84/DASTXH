-- =========================================================
-- DASTXH - Schema base v2
--
-- Preparado para:
--   - CLI
--   - futura GUI web
--   - historial consultable
--   - persistencia de artefactos/reportes
--
-- Tablas:
--   executions        : historial principal de ejecuciones
--   header_results    : capa 1 (curl custom)
--   hsecscan_results  : capa 2 (hsecscan)
--   xss_results       : capa 3 (dalfox)
--   artifacts         : archivos generados por ejecución
--
-- Vista:
--   vw_execution_summary : resumen cómodo para historial GUI / consultas
-- =========================================================

-- =========================================================
-- 1) EJECUCIONES
-- =========================================================
CREATE TABLE IF NOT EXISTS executions (
  id                BIGSERIAL PRIMARY KEY,
  target_url        TEXT NOT NULL,
  started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at       TIMESTAMPTZ NULL,
  status            TEXT NOT NULL
                    CHECK (status IN ('initiated', 'running', 'finished', 'failed')),
  error_message     TEXT NULL,

  -- Trazabilidad del origen de la ejecución
  request_source    TEXT NOT NULL DEFAULT 'cli'
                    CHECK (request_source IN ('cli', 'web', 'api')),

  -- Soporte para ejecuciones por archivo/lista
  urls_ingresadas   INT NOT NULL DEFAULT 1 CHECK (urls_ingresadas >= 0),
  urls_evaluadas    INT NOT NULL DEFAULT 0 CHECK (urls_evaluadas >= 0),

  -- Ruta base de reportes de esta ejecución dentro de /work
  report_dir        TEXT NULL
);

CREATE INDEX IF NOT EXISTS ix_executions_started_at
  ON executions (started_at DESC);

CREATE INDEX IF NOT EXISTS ix_executions_status
  ON executions (status);

CREATE INDEX IF NOT EXISTS ix_executions_request_source
  ON executions (request_source);

-- =========================================================
-- 2) RESULTADOS CAPA 1: HEADERS CUSTOM (curl)
-- =========================================================
CREATE TABLE IF NOT EXISTS header_results (
  execution_id         BIGINT PRIMARY KEY
                       REFERENCES executions(id) ON DELETE CASCADE,

  headers_evaluadas    INT NOT NULL CHECK (headers_evaluadas >= 0),
  headers_presentes    INT NOT NULL CHECK (headers_presentes >= 0),
  cumplimiento_pct     NUMERIC(6,2) NOT NULL
                       CHECK (cumplimiento_pct >= 0 AND cumplimiento_pct <= 100),

  present_json         JSONB NOT NULL,
  missing_json         JSONB NOT NULL,
  raw_headers_json     JSONB NOT NULL,
  cookies_flags_json   JSONB NULL,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =========================================================
-- 3) RESULTADOS CAPA 2: HSECSCAN
-- =========================================================
CREATE TABLE IF NOT EXISTS hsecscan_results (
  execution_id         BIGINT PRIMARY KEY
                       REFERENCES executions(id) ON DELETE CASCADE,

  tool_rc              INT NOT NULL,
  raw_output           TEXT NOT NULL,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =========================================================
-- 4) RESULTADOS CAPA 3: DALFOX / XSS
-- =========================================================
CREATE TABLE IF NOT EXISTS xss_results (
  execution_id         BIGINT PRIMARY KEY
                       REFERENCES executions(id) ON DELETE CASCADE,

  tool_rc              INT NOT NULL DEFAULT 0,
  findings_count       INT NOT NULL CHECK (findings_count >= 0),
  summary_json         JSONB NOT NULL,
  raw_output           TEXT NOT NULL,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =========================================================
-- 5) ARTEFACTOS / REPORTES GENERADOS
--    Aquí registraremos los archivos creados en /work/reports/...
-- =========================================================
CREATE TABLE IF NOT EXISTS artifacts (
  id                   BIGSERIAL PRIMARY KEY,

  execution_id         BIGINT NOT NULL
                       REFERENCES executions(id) ON DELETE CASCADE,

  artifact_type        TEXT NOT NULL
                       CHECK (
                         artifact_type IN (
                           'report_md',
                           'report_html',
                           'report_pdf',
                           'headers_json',
                           'hsecscan_txt',
                           'dalfox_json',
                           'dalfox_txt',
                           'run_meta_json',
                           'other'
                         )
                       ),

  file_name            TEXT NOT NULL,
  relative_path        TEXT NOT NULL,
  mime_type            TEXT NULL,
  size_bytes           BIGINT NULL CHECK (size_bytes IS NULL OR size_bytes >= 0),

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_artifacts_execution_id
  ON artifacts (execution_id);

CREATE INDEX IF NOT EXISTS ix_artifacts_artifact_type
  ON artifacts (artifact_type);

CREATE UNIQUE INDEX IF NOT EXISTS ux_artifacts_execution_relative_path
  ON artifacts (execution_id, relative_path);

-- =========================================================
-- 6) VISTA DE RESUMEN PARA HISTORIAL
--    Útil para GUI, API y consultas manuales
-- =========================================================
CREATE OR REPLACE VIEW vw_execution_summary AS
SELECT
  e.id,
  e.target_url,
  e.started_at,
  e.finished_at,
  e.status,
  e.request_source,
  e.urls_ingresadas,
  e.urls_evaluadas,
  e.report_dir,

  hr.headers_evaluadas,
  hr.headers_presentes,
  hr.cumplimiento_pct,

  hs.tool_rc AS hsecscan_rc,

  xr.tool_rc AS dalfox_rc,
  xr.findings_count AS xss_findings_count,

  COUNT(a.id) AS artifacts_count
FROM executions e
LEFT JOIN header_results hr
  ON hr.execution_id = e.id
LEFT JOIN hsecscan_results hs
  ON hs.execution_id = e.id
LEFT JOIN xss_results xr
  ON xr.execution_id = e.id
LEFT JOIN artifacts a
  ON a.execution_id = e.id
GROUP BY
  e.id,
  e.target_url,
  e.started_at,
  e.finished_at,
  e.status,
  e.request_source,
  e.urls_ingresadas,
  e.urls_evaluadas,
  e.report_dir,
  hr.headers_evaluadas,
  hr.headers_presentes,
  hr.cumplimiento_pct,
  hs.tool_rc,
  xr.tool_rc,
  xr.findings_count;