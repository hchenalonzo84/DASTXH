-- =========================================================
-- DASTXH - Schema base v5
--
-- Objetivo de esta versión:
--   - conservar executions como entidad principal
--   - guardar perfil de escaneo y uso interno de hsecscan
--   - persistir resultados normalizados de headers, cookies y XSS
--   - agregar score HTTP, grade HTTP y pruebas HTTP detalladas
--
-- Tablas principales:
--   executions        : historial principal de ejecuciones
--   header_results    : resumen agregado HTTP
--   header_checks     : detalle por cabecera requerida
--   cookie_checks     : detalle por cookie detectada
--   http_tests        : pruebas HTTP detalladas (A/B/C + CORS)
--   hsecscan_results  : resumen/evidencia capa 2
--   xss_results       : resumen/evidencia capa 3
--   xss_findings      : hallazgos XSS normalizados por ejecución
--   artifacts         : archivos generados por ejecución
--
-- Vista:
--   vw_execution_summary : resumen para historial GUI / consultas
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

  request_source    TEXT NOT NULL DEFAULT 'cli'
                    CHECK (request_source IN ('cli', 'web', 'api')),

  scan_profile      TEXT NOT NULL DEFAULT 'superficial'
                    CHECK (scan_profile IN ('superficial', 'profundo')),

  enable_hsecscan   BOOLEAN NOT NULL DEFAULT FALSE,

  urls_ingresadas   INT NOT NULL DEFAULT 1 CHECK (urls_ingresadas >= 0),
  urls_evaluadas    INT NOT NULL DEFAULT 0 CHECK (urls_evaluadas >= 0),

  report_dir        TEXT NULL
);

CREATE INDEX IF NOT EXISTS ix_executions_started_at
  ON executions (started_at DESC);

CREATE INDEX IF NOT EXISTS ix_executions_status
  ON executions (status);

CREATE INDEX IF NOT EXISTS ix_executions_request_source
  ON executions (request_source);

CREATE INDEX IF NOT EXISTS ix_executions_scan_profile
  ON executions (scan_profile);


-- =========================================================
-- 2) RESULTADOS HTTP: RESUMEN
-- =========================================================
CREATE TABLE IF NOT EXISTS header_results (
  execution_id         BIGINT PRIMARY KEY
                       REFERENCES executions(id) ON DELETE CASCADE,

  headers_evaluadas    INT NOT NULL CHECK (headers_evaluadas >= 0),
  headers_presentes    INT NOT NULL CHECK (headers_presentes >= 0),
  cumplimiento_pct     NUMERIC(6,2) NOT NULL
                       CHECK (cumplimiento_pct >= 0 AND cumplimiento_pct <= 100),

  http_score           INT NOT NULL
                       CHECK (http_score >= 0 AND http_score <= 100),

  http_grade           TEXT NOT NULL
                       CHECK (http_grade IN ('A', 'B', 'C', 'D', 'F')),

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =========================================================
-- 3) RESULTADOS HTTP: DETALLE POR HEADER REQUERIDO
-- =========================================================
CREATE TABLE IF NOT EXISTS header_checks (
  id                   BIGSERIAL PRIMARY KEY,

  execution_id         BIGINT NOT NULL
                       REFERENCES executions(id) ON DELETE CASCADE,

  header_name          TEXT NOT NULL,
  is_present           BOOLEAN NOT NULL,
  header_value         TEXT NULL,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT ux_header_checks_execution_header
    UNIQUE (execution_id, header_name)
);

CREATE INDEX IF NOT EXISTS ix_header_checks_execution_id
  ON header_checks (execution_id);

CREATE INDEX IF NOT EXISTS ix_header_checks_present
  ON header_checks (is_present);


-- =========================================================
-- 4) RESULTADOS HTTP: DETALLE POR COOKIE
-- =========================================================
CREATE TABLE IF NOT EXISTS cookie_checks (
  id                   BIGSERIAL PRIMARY KEY,

  execution_id         BIGINT NOT NULL
                       REFERENCES executions(id) ON DELETE CASCADE,

  cookie_name          TEXT NULL,
  cookie_raw           TEXT NOT NULL,

  secure               BOOLEAN NOT NULL DEFAULT FALSE,
  httponly             BOOLEAN NOT NULL DEFAULT FALSE,
  samesite_present     BOOLEAN NOT NULL DEFAULT FALSE,
  samesite_value       TEXT NULL,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_cookie_checks_execution_id
  ON cookie_checks (execution_id);


-- =========================================================
-- 5) RESULTADOS HTTP: PRUEBAS DETALLADAS
-- =========================================================
CREATE TABLE IF NOT EXISTS http_tests (
  id                   BIGSERIAL PRIMARY KEY,

  execution_id         BIGINT NOT NULL
                       REFERENCES executions(id) ON DELETE CASCADE,

  test_id              TEXT NOT NULL,
  name                 TEXT NOT NULL,
  category             TEXT NOT NULL,
  status               TEXT NOT NULL
                       CHECK (status IN ('passed', 'failed', 'warning', 'info')),
  score_delta          INT NOT NULL,

  reason               TEXT NOT NULL,
  recommendation       TEXT NOT NULL,

  header_name          TEXT NULL,
  header_value         TEXT NULL,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT ux_http_tests_execution_test
    UNIQUE (execution_id, test_id)
);

CREATE INDEX IF NOT EXISTS ix_http_tests_execution_id
  ON http_tests (execution_id);

CREATE INDEX IF NOT EXISTS ix_http_tests_status
  ON http_tests (status);

CREATE INDEX IF NOT EXISTS ix_http_tests_category
  ON http_tests (category);


-- =========================================================
-- 6) RESULTADOS CAPA 2: HSECSCAN
-- =========================================================
CREATE TABLE IF NOT EXISTS hsecscan_results (
  execution_id         BIGINT PRIMARY KEY
                       REFERENCES executions(id) ON DELETE CASCADE,

  tool_rc              INT NOT NULL,
  raw_output           TEXT NOT NULL,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =========================================================
-- 7) RESULTADOS CAPA 3: DALFOX / XSS (RESUMEN)
-- =========================================================
CREATE TABLE IF NOT EXISTS xss_results (
  execution_id         BIGINT PRIMARY KEY
                       REFERENCES executions(id) ON DELETE CASCADE,

  tool_rc              INT NOT NULL DEFAULT 0,
  findings_count       INT NOT NULL CHECK (findings_count >= 0),
  summary_json         JSONB NULL,
  raw_output           TEXT NOT NULL,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- =========================================================
-- 8) RESULTADOS CAPA 3: HALLAZGOS XSS NORMALIZADOS
-- =========================================================
CREATE TABLE IF NOT EXISTS xss_findings (
  id                   BIGSERIAL PRIMARY KEY,

  execution_id         BIGINT NOT NULL
                       REFERENCES executions(id) ON DELETE CASCADE,

  finding_order        INT NOT NULL DEFAULT 0,
  source_type          TEXT NULL,
  target_url           TEXT NULL,
  param_name           TEXT NULL,
  payload              TEXT NULL,
  evidence             TEXT NULL,
  severity             TEXT NULL,
  raw_finding_json     JSONB NULL,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT ux_xss_findings_execution_order
    UNIQUE (execution_id, finding_order)
);

CREATE INDEX IF NOT EXISTS ix_xss_findings_execution_id
  ON xss_findings (execution_id);

CREATE INDEX IF NOT EXISTS ix_xss_findings_severity
  ON xss_findings (severity);


-- =========================================================
-- 9) ARTEFACTOS / REPORTES GENERADOS
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
-- 10) VISTA DE RESUMEN PARA HISTORIAL
-- =========================================================
CREATE OR REPLACE VIEW vw_execution_summary AS
SELECT
  e.id,
  e.target_url,
  e.started_at,
  e.finished_at,
  e.status,
  e.request_source,
  e.scan_profile,
  e.enable_hsecscan,
  e.urls_ingresadas,
  e.urls_evaluadas,
  e.report_dir,

  hr.headers_evaluadas,
  hr.headers_presentes,
  hr.cumplimiento_pct,
  hr.http_score,
  hr.http_grade,

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
  e.scan_profile,
  e.enable_hsecscan,
  e.urls_ingresadas,
  e.urls_evaluadas,
  e.report_dir,
  hr.headers_evaluadas,
  hr.headers_presentes,
  hr.cumplimiento_pct,
  hr.http_score,
  hr.http_grade,
  hs.tool_rc,
  xr.tool_rc,
  xr.findings_count;