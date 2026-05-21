-- =========================================================
-- DASTXH - Schema base v10
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
--   - persistir traducciones IA para hsecscan:
--       * security_description_es
--       * recommendations_es
--       * cwe_es
--       * translation_model_name
--       * translated_at
--   - persistir análisis de cookies con reglas + IA:
--       * risk_level
--       * cwe_mappings
--       * interpretation_humana
--       * recommended_action
--       * model_name
--       * interpreted_at
--   - persistir reporte general profesional:
--       * versión actual editable
--       * historial de versiones solo lectura
--       * exportaciones PDF trazables
--
-- Decisión de diseño:
--   professional_reports guarda la versión actual editable.
--   professional_report_versions guarda fotografías históricas.
--   professional_report_pdf_exports vincula una versión histórica con
--   el artifact PDF generado.
--
-- Nota:
--   Las versiones históricas del reporte general no deben editarse
--   desde la aplicación. Para reforzar esto, se agrega un trigger que
--   bloquea UPDATE sobre professional_report_versions.
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
--
-- Campos técnicos originales:
--   cookie_name
--   cookie_raw
--   secure
--   httponly
--   samesite_present
--   samesite_value
--
-- Campos de análisis DASTXH:
--   risk_level:
--     alta, media, baja, informativa
--
--   cwe_mappings:
--     JSONB con debilidades asociadas, por ejemplo:
--       CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
--       CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
--       CWE-1275: Sensitive Cookie with Improper SameSite Attribute
--
--   interpretation_humana:
--     explicación breve en español latino generada por IA,
--     basada en reglas internas y evidencia técnica.
--
--   recommended_action:
--     recomendación breve para revisar o corregir atributos de cookie.
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

  risk_level           TEXT NULL
                       CHECK (
                         risk_level IS NULL OR
                         risk_level IN ('alta', 'media', 'baja', 'informativa')
                       ),

  cwe_mappings         JSONB NULL,

  interpretation_humana TEXT NULL,
  recommended_action    TEXT NULL,
  model_name            TEXT NULL,
  interpreted_at        TIMESTAMPTZ NULL,

  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Compatibilidad si la tabla cookie_checks ya existía antes de v9.
ALTER TABLE cookie_checks
  ADD COLUMN IF NOT EXISTS risk_level TEXT NULL;

ALTER TABLE cookie_checks
  ADD COLUMN IF NOT EXISTS cwe_mappings JSONB NULL;

ALTER TABLE cookie_checks
  ADD COLUMN IF NOT EXISTS interpretation_humana TEXT NULL;

ALTER TABLE cookie_checks
  ADD COLUMN IF NOT EXISTS recommended_action TEXT NULL;

ALTER TABLE cookie_checks
  ADD COLUMN IF NOT EXISTS model_name TEXT NULL;

ALTER TABLE cookie_checks
  ADD COLUMN IF NOT EXISTS interpreted_at TIMESTAMPTZ NULL;

-- Compatibilidad para agregar CHECK de risk_level si la tabla venía de versión anterior.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'cookie_checks_risk_level_check'
      AND conrelid = 'cookie_checks'::regclass
  ) THEN
    ALTER TABLE cookie_checks
      ADD CONSTRAINT cookie_checks_risk_level_check
      CHECK (
        risk_level IS NULL OR
        risk_level IN ('alta', 'media', 'baja', 'informativa')
      );
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS ix_cookie_checks_execution_id
  ON cookie_checks (execution_id);

CREATE INDEX IF NOT EXISTS ix_cookie_checks_risk_level
  ON cookie_checks (risk_level);

CREATE INDEX IF NOT EXISTS ix_cookie_checks_interpreted_at
  ON cookie_checks (interpreted_at);


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
--
-- Campos originales:
--   security_description
--   recommendations
--   cwe
--
-- Campos traducidos por IA:
--   security_description_es
--   recommendations_es
--   cwe_es
--
-- Las columnas traducidas no sustituyen la evidencia original.
-- Solo se usan para mostrar una versión más legible en español latino
-- dentro de la GUI.
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

  -- Texto original reportado por hsecscan.
  security_description  TEXT NULL,
  security_reference    TEXT NULL,
  recommendations       TEXT NULL,
  cwe                   TEXT NULL,
  cwe_url               TEXT NULL,
  https                 TEXT NULL,

  -- Traducciones generadas por IA local.
  security_description_es TEXT NULL,
  recommendations_es      TEXT NULL,
  cwe_es                  TEXT NULL,
  translation_model_name  TEXT NULL,
  translated_at           TIMESTAMPTZ NULL,

  raw_check_json        JSONB NULL,

  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Compatibilidad si la tabla hsecscan_checks ya existía antes de v8.
ALTER TABLE hsecscan_checks
  ADD COLUMN IF NOT EXISTS security_description_es TEXT NULL;

ALTER TABLE hsecscan_checks
  ADD COLUMN IF NOT EXISTS recommendations_es TEXT NULL;

ALTER TABLE hsecscan_checks
  ADD COLUMN IF NOT EXISTS cwe_es TEXT NULL;

ALTER TABLE hsecscan_checks
  ADD COLUMN IF NOT EXISTS translation_model_name TEXT NULL;

ALTER TABLE hsecscan_checks
  ADD COLUMN IF NOT EXISTS translated_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS ix_hsecscan_checks_execution_id
  ON hsecscan_checks (execution_id);

CREATE INDEX IF NOT EXISTS ix_hsecscan_checks_record_type
  ON hsecscan_checks (record_type);

CREATE INDEX IF NOT EXISTS ix_hsecscan_checks_header_name
  ON hsecscan_checks (header_name);

CREATE INDEX IF NOT EXISTS ix_hsecscan_checks_risk_level
  ON hsecscan_checks (risk_level);

CREATE INDEX IF NOT EXISTS ix_hsecscan_checks_translated_at
  ON hsecscan_checks (translated_at);


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
                           'professional_report_md',
                           'professional_report_html',
                           'professional_report_pdf',
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
        'professional_report_md',
        'professional_report_html',
        'professional_report_pdf',
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
-- 11) REPORTE GENERAL PROFESIONAL: VERSIÓN ACTUAL EDITABLE
--
-- Esta tabla guarda el estado actual editable del reporte general.
--
-- Regla:
--   - Solo esta tabla se edita desde el formulario.
--   - Cada guardado debe crear una fotografía histórica en
--     professional_report_versions.
-- =========================================================
CREATE TABLE IF NOT EXISTS professional_reports (
  id                       BIGSERIAL PRIMARY KEY,

  execution_id             BIGINT NOT NULL
                           REFERENCES executions(id) ON DELETE CASCADE,

  current_version_number   INT NOT NULL DEFAULT 0
                           CHECK (current_version_number >= 0),

  -- Se llena después de crear professional_report_versions.
  current_version_id       BIGINT NULL,

  status                   TEXT NOT NULL DEFAULT 'draft'
                           CHECK (
                             status IN (
                               'draft',
                               'ai_generated',
                               'edited',
                               'pdf_exported',
                               'archived'
                             )
                           ),

  generated_by_ai          BOOLEAN NOT NULL DEFAULT FALSE,
  ai_model_name            TEXT NULL,

  report_title             TEXT NOT NULL DEFAULT 'Reporte general DASTXH',

  executive_summary        TEXT NULL,
  scope_text               TEXT NULL,
  methodology_text         TEXT NULL,
  headers_analysis         TEXT NULL,
  hsecscan_analysis        TEXT NULL,
  cookies_analysis         TEXT NULL,
  xss_analysis             TEXT NULL,
  prioritized_findings     TEXT NULL,
  general_recommendations  TEXT NULL,
  limitations_text         TEXT NULL,
  conclusion_text          TEXT NULL,
  analyst_notes            TEXT NULL,

  created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT ux_professional_reports_execution
    UNIQUE (execution_id)
);

-- Compatibilidad si la tabla ya existía parcialmente.
ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS current_version_number INT NOT NULL DEFAULT 0;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS current_version_id BIGINT NULL;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'draft';

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS generated_by_ai BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS ai_model_name TEXT NULL;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS report_title TEXT NOT NULL DEFAULT 'Reporte general DASTXH';

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS executive_summary TEXT NULL;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS scope_text TEXT NULL;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS methodology_text TEXT NULL;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS headers_analysis TEXT NULL;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS hsecscan_analysis TEXT NULL;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS cookies_analysis TEXT NULL;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS xss_analysis TEXT NULL;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS prioritized_findings TEXT NULL;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS general_recommendations TEXT NULL;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS limitations_text TEXT NULL;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS conclusion_text TEXT NULL;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS analyst_notes TEXT NULL;

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE professional_reports
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS ix_professional_reports_execution_id
  ON professional_reports (execution_id);

CREATE INDEX IF NOT EXISTS ix_professional_reports_status
  ON professional_reports (status);

CREATE INDEX IF NOT EXISTS ix_professional_reports_updated_at
  ON professional_reports (updated_at DESC);


-- =========================================================
-- 11.1) REPORTE GENERAL PROFESIONAL: VERSIONES HISTÓRICAS
--
-- Esta tabla guarda una fotografía completa del reporte cada vez
-- que se genera con IA, se guarda manualmente o se prepara para PDF.
--
-- Regla:
--   - Las versiones históricas son solo lectura.
--   - La aplicación no debe editarlas.
--   - La tabla tiene un trigger para bloquear UPDATE.
--
-- Nota:
--   Se bloquea UPDATE porque la regla principal es que una versión
--   creada no debe modificarse. No se bloquea DELETE para evitar
--   interferir con borrados en cascada si en el futuro se elimina una
--   ejecución completa.
-- =========================================================
CREATE TABLE IF NOT EXISTS professional_report_versions (
  id                       BIGSERIAL PRIMARY KEY,

  professional_report_id   BIGINT NOT NULL
                           REFERENCES professional_reports(id) ON DELETE CASCADE,

  execution_id             BIGINT NOT NULL
                           REFERENCES executions(id) ON DELETE CASCADE,

  version_number           INT NOT NULL
                           CHECK (version_number > 0),

  version_label            TEXT NULL,

  change_type              TEXT NOT NULL
                           CHECK (
                             change_type IN (
                               'ai_generated',
                               'manual_save',
                               'pdf_export_snapshot'
                             )
                           ),

  change_reason            TEXT NULL,

  -- Fotografía completa del contenido editable en ese momento.
  snapshot_json            JSONB NOT NULL,

  -- Hash opcional para detectar cambios de contenido.
  content_hash             TEXT NULL,

  created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by               TEXT NOT NULL DEFAULT 'web',

  CONSTRAINT ux_professional_report_versions_report_version
    UNIQUE (professional_report_id, version_number)
);

CREATE INDEX IF NOT EXISTS ix_professional_report_versions_report_id
  ON professional_report_versions (professional_report_id);

CREATE INDEX IF NOT EXISTS ix_professional_report_versions_execution_id
  ON professional_report_versions (execution_id);

CREATE INDEX IF NOT EXISTS ix_professional_report_versions_created_at
  ON professional_report_versions (created_at DESC);

CREATE INDEX IF NOT EXISTS ix_professional_report_versions_change_type
  ON professional_report_versions (change_type);

-- Relación desde professional_reports hacia su versión actual.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'professional_reports_current_version_fk'
      AND conrelid = 'professional_reports'::regclass
  ) THEN
    ALTER TABLE professional_reports
      ADD CONSTRAINT professional_reports_current_version_fk
      FOREIGN KEY (current_version_id)
      REFERENCES professional_report_versions(id)
      ON DELETE SET NULL;
  END IF;
END $$;


-- =========================================================
-- 11.2) FUNCIÓN Y TRIGGER PARA BLOQUEAR EDICIÓN DE VERSIONES
-- =========================================================
CREATE OR REPLACE FUNCTION prevent_professional_report_version_update()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION
    'Las versiones históricas del reporte general son solo lectura y no pueden editarse.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_professional_report_version_update
  ON professional_report_versions;

CREATE TRIGGER trg_prevent_professional_report_version_update
BEFORE UPDATE ON professional_report_versions
FOR EACH ROW
EXECUTE FUNCTION prevent_professional_report_version_update();


-- =========================================================
-- 11.3) REPORTE GENERAL PROFESIONAL: EXPORTACIONES PDF
--
-- Registra cada PDF generado desde una versión histórica exacta.
--
-- El archivo físico se registra también en artifacts.
-- Esta tabla vincula:
--   - reporte
--   - versión usada
--   - ejecución
--   - artifact PDF generado
-- =========================================================
CREATE TABLE IF NOT EXISTS professional_report_pdf_exports (
  id                               BIGSERIAL PRIMARY KEY,

  professional_report_id           BIGINT NOT NULL
                                   REFERENCES professional_reports(id) ON DELETE CASCADE,

  professional_report_version_id   BIGINT NOT NULL
                                   REFERENCES professional_report_versions(id) ON DELETE CASCADE,

  execution_id                     BIGINT NOT NULL
                                   REFERENCES executions(id) ON DELETE CASCADE,

  artifact_id                      BIGINT NULL
                                   REFERENCES artifacts(id) ON DELETE SET NULL,

  pdf_file_name                    TEXT NOT NULL,
  pdf_relative_path                TEXT NOT NULL,

  exported_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  exported_by                      TEXT NOT NULL DEFAULT 'web'
);

CREATE INDEX IF NOT EXISTS ix_professional_report_pdf_exports_report_id
  ON professional_report_pdf_exports (professional_report_id);

CREATE INDEX IF NOT EXISTS ix_professional_report_pdf_exports_version_id
  ON professional_report_pdf_exports (professional_report_version_id);

CREATE INDEX IF NOT EXISTS ix_professional_report_pdf_exports_execution_id
  ON professional_report_pdf_exports (execution_id);

CREATE INDEX IF NOT EXISTS ix_professional_report_pdf_exports_artifact_id
  ON professional_report_pdf_exports (artifact_id);

CREATE INDEX IF NOT EXISTS ix_professional_report_pdf_exports_exported_at
  ON professional_report_pdf_exports (exported_at DESC);
-- =========================================================
-- 12) VISTA DE RESUMEN PARA HISTORIAL
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

  COUNT(DISTINCT cc.id) AS cookie_checks_count,

  COUNT(
    DISTINCT cc.id
  ) FILTER (
    WHERE
      cc.interpretation_humana IS NOT NULL
      OR cc.recommended_action IS NOT NULL
      OR cc.cwe_mappings IS NOT NULL
      OR cc.risk_level IS NOT NULL
  ) AS cookie_interpreted_checks_count,

  COUNT(DISTINCT hsc.id) AS hsecscan_checks_count,

  COUNT(
    DISTINCT hsc.id
  ) FILTER (
    WHERE
      hsc.security_description_es IS NOT NULL
      OR hsc.recommendations_es IS NOT NULL
      OR hsc.cwe_es IS NOT NULL
  ) AS hsecscan_translated_checks_count,

  COUNT(DISTINCT xag.id) AS xss_ai_groups_count,
  COUNT(DISTINCT a.id) AS artifacts_count,

  pr.id AS professional_report_id,
  pr.current_version_number AS professional_report_current_version,
  pr.status AS professional_report_status,
  pr.updated_at AS professional_report_updated_at,

  COUNT(DISTINCT prv.id) AS professional_report_versions_count,
  COUNT(DISTINCT prpdf.id) AS professional_report_pdf_exports_count

FROM executions e
LEFT JOIN header_results hr
  ON hr.execution_id = e.id
LEFT JOIN cookie_checks cc
  ON cc.execution_id = e.id
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
LEFT JOIN professional_reports pr
  ON pr.execution_id = e.id
LEFT JOIN professional_report_versions prv
  ON prv.professional_report_id = pr.id
LEFT JOIN professional_report_pdf_exports prpdf
  ON prpdf.professional_report_id = pr.id
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
  xr.findings_count,
  pr.id,
  pr.current_version_number,
  pr.status,
  pr.updated_at;