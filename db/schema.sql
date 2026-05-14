-- =========================================================
-- DASTXH - Schema base v7
--
-- Objetivo de esta versión:
--   - conservar executions como entidad principal
--   - persistir resultados HTTP normalizados
--   - persistir XSS normalizado
--   - persistir agrupación XSS preparada para IA
--   - persistir hsecscan como segunda capa de validación:
--       * salida cruda
--       * salida estructurada JSON
--       * checks normalizados observados/faltantes
--       * artifact hsecscan.json
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

  -- JSON completo generado por parse_hsecscan_output(...)
  structured_json      JSONB NULL,

  -- Resumen interno para consultas rápidas:
  -- status_code, counts, missing_header_names, observed_header_names, etc.
  summary_json         JSONB NULL,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Compatibilidad si la tabla ya existía antes de v7.
ALTER TABLE hsecscan_results
  ADD COLUMN IF NOT EXISTS structured_json JSONB NULL;

ALTER TABLE hsecscan_results
  ADD COLUMN IF NOT EXISTS summary_json JSONB NULL;


-- =========================================================
-- 6.1) RESULTADOS CAPA 2: HSECSCAN NORMALIZADO
--
-- Guarda cada registro estructurado de hsecscan:
--   - cabeceras observadas con advertencia
--   - cabeceras faltantes
-- =========================================================
CREATE TABLE IF NOT EXISTS hsecscan_checks (
  id                    BIGSERIAL PRIMARY KEY,

  execution_id          BIGINT NOT NULL
                        REFERENCES executions(id) ON DELETE CASCADE,

  record_type           TEXT NOT NULL
                        CHECK (record_type IN ('observed', 'missing')),

  display_status        TEXT NULL,
  header_name           TEXT NOT NULL,
  header_value          TEXT NULL,

  risk_level            TEXT NULL
                        CHECK (
                          risk_level IS NULL OR
                          risk_level IN ('alta', 'media', 'baja', 'informativa')
                        ),

  reference_url         TEXT NULL,
  security_description  TEXT NULL,
  security_reference    TEXT NULL,
  recommendations       TEXT NULL,
  cwe                   TEXT NULL,
  cwe_url               TEXT NULL,
  https                 TEXT NULL,

  raw_check_json        JSONB NULL,

  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_hsecscan_checks_execution_id
  ON hsecscan_checks (execution_id);

CREATE INDEX IF NOT EXISTS ix_hsecscan_checks_record_type
  ON hsecscan_checks (record_type);

CREATE INDEX IF NOT EXISTS ix_hsecscan_checks_header_name
  ON hsecscan_checks (header_name);

CREATE INDEX IF NOT EXISTS ix_hsecscan_checks_risk_level
  ON hsecscan_checks (risk_level);
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
-- 9) AGRUPACIÓN XSS PREPARADA PARA IA
-- =========================================================
CREATE TABLE IF NOT EXISTS xss_ai_groups (
  id                     BIGSERIAL PRIMARY KEY,

  execution_id           BIGINT NOT NULL
                         REFERENCES executions(id) ON DELETE CASCADE,

  group_order            INT NOT NULL CHECK (group_order > 0),
  entry_type             TEXT NOT NULL
                         CHECK (entry_type IN ('individual', 'group')),

  parameter_probable     TEXT NULL,
  context_probable       TEXT NULL,
  severity_mode          TEXT NULL,
  payload_signature      TEXT NULL,
  occurrences            INT NOT NULL DEFAULT 1 CHECK (occurrences >= 1),
  target_url             TEXT NULL,

  sample_finding_orders  JSONB NULL,
  sample_payloads        JSONB NULL,
  sample_evidence        JSONB NULL,

  interpretation_humana  TEXT NULL,
  risk_summary           TEXT NULL,
  likely_root_cause      TEXT NULL,
  recommended_review_area TEXT NULL,
  confidence             TEXT NULL,
  model_name             TEXT NULL,

  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT ux_xss_ai_groups_execution_order
    UNIQUE (execution_id, group_order)
);

CREATE INDEX IF NOT EXISTS ix_xss_ai_groups_execution_id
  ON xss_ai_groups (execution_id);

CREATE INDEX IF NOT EXISTS ix_xss_ai_groups_entry_type
  ON xss_ai_groups (entry_type);

CREATE INDEX IF NOT EXISTS ix_xss_ai_groups_severity_mode
  ON xss_ai_groups (severity_mode);


-- =========================================================
-- 10) ARTEFACTOS / REPORTES GENERADOS
-- =========================================================
CREATE TABLE IF NOT EXISTS artifacts (
  id                   BIGSERIAL PRIMARY KEY,

  execution_id         BIGINT NOT NULL
                       REFERENCES executions(id) ON DELETE CASCADE,

  artifact_type        TEXT NOT NULL
                       CONSTRAINT artifacts_artifact_type_check
                       CHECK (
                         artifact_type IN (
                           'report_md',
                           'report_html',
                           'report_pdf',
                           'headers_json',
                           'hsecscan_txt',
                           'hsecscan_json',
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

-- Compatibilidad si la tabla artifacts ya existía con el CHECK anterior.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'artifacts_artifact_type_check'
      AND conrelid = 'artifacts'::regclass
  ) THEN
    ALTER TABLE artifacts
      DROP CONSTRAINT artifacts_artifact_type_check;
  END IF;

  ALTER TABLE artifacts
    ADD CONSTRAINT artifacts_artifact_type_check
    CHECK (
      artifact_type IN (
        'report_md',
        'report_html',
        'report_pdf',
        'headers_json',
        'hsecscan_txt',
        'hsecscan_json',
        'dalfox_json',
        'dalfox_txt',
        'run_meta_json',
        'other'
      )
    );
END $$;

CREATE INDEX IF NOT EXISTS ix_artifacts_execution_id
  ON artifacts (execution_id);

CREATE INDEX IF NOT EXISTS ix_artifacts_artifact_type
  ON artifacts (artifact_type);

CREATE UNIQUE INDEX IF NOT EXISTS ux_artifacts_execution_relative_path
  ON artifacts (execution_id, relative_path);
-- =========================================================
-- 11) VISTA DE RESUMEN PARA HISTORIAL
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

  CASE
    WHEN hs.summary_json IS NULL THEN NULL
    ELSE NULLIF(hs.summary_json ->> 'missing_security_headers_count', '')::INT
  END AS hsecscan_missing_headers_count,

  CASE
    WHEN hs.summary_json IS NULL THEN NULL
    ELSE NULLIF(hs.summary_json ->> 'observed_security_headers_count', '')::INT
  END AS hsecscan_observed_headers_count,

  CASE
    WHEN hs.summary_json IS NULL THEN NULL
    ELSE NULLIF(hs.summary_json ->> 'total_hsecscan_records', '')::INT
  END AS hsecscan_records_count,

  xr.tool_rc AS dalfox_rc,
  xr.findings_count AS xss_findings_count,

  COUNT(DISTINCT hsc.id) AS hsecscan_checks_count,
  COUNT(DISTINCT xag.id) AS xss_ai_groups_count,
  COUNT(DISTINCT a.id) AS artifacts_count
FROM executions e
LEFT JOIN header_results hr
  ON hr.execution_id = e.id
LEFT JOIN hsecscan_results hs
  ON hs.execution_id = e.id
LEFT JOIN hsecscan_checks hsc
  ON hsc.execution_id = e.id
LEFT JOIN xss_results xr
  ON xr.execution_id = e.id
LEFT JOIN xss_ai_groups xag
  ON xag.execution_id = e.id
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
  hs.summary_json,
  xr.tool_rc,
  xr.findings_count;