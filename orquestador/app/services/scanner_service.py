"""
scanner_service.py
- Servicio reutilizable para ejecutar una evaluación completa DASTXH.
- Su objetivo es encapsular el pipeline de escaneo en una función
  reutilizable desde:
  * CLI
  * GUI web
  * endpoints API

Flujo principal:
  1) Inserta ejecución en PostgreSQL
  2) Marca estado como running
  3) Ejecuta Capa 1 (curl custom)
  4) Ejecuta Capa 2 (hsecscan)
  5) Ejecuta Capa 3 (Dalfox)
  6) Genera report.md y report.html
  7) Registra artifacts
  8) Marca ejecución como finished o failed
  9) Devuelve un resumen estructurado del resultado
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

import db as db_layer
from config import (
    ARTIFACT_TYPE_DALFOX_JSON,
    ARTIFACT_TYPE_DALFOX_TXT,
    ARTIFACT_TYPE_HEADERS_JSON,
    ARTIFACT_TYPE_HSECSCAN_TXT,
    ARTIFACT_TYPE_REPORT_HTML,
    ARTIFACT_TYPE_REPORT_MD,
    ARTIFACT_TYPE_RUN_META_JSON,
    DALFOX_JSON,
    DALFOX_TXT,
    HEADERS_JSON,
    HSECSCAN_TXT,
    MIME_APPLICATION_JSON,
    MIME_TEXT_HTML,
    MIME_TEXT_MARKDOWN,
    MIME_TEXT_PLAIN,
    REPORT_HTML,
    REPORT_MD,
    RUN_META_JSON,
)
from report import build_report_html, build_report_md
from tools.curl_custom import curl_fetch_headers, evaluate_headers_and_cookies
from tools.dalfox_tool import read_summary, run_dalfox
from tools.hsecscan_tool import run_hsecscan
from utils import ensure_dir, safe_read_text, ts_folder, utc_now, write_json


# ==========================================================
# HELPERS INTERNOS
# ==========================================================

def _file_size_or_none(path: Path) -> Optional[int]:
    """
    Devuelve el tamaño del archivo en bytes si existe.
    En caso contrario, devuelve None.
    """
    try:
        if path.exists() and path.is_file():
            return int(path.stat().st_size)
    except Exception:
        return None
    return None


def _register_file_artifact(
    dsn: str,
    execution_id: int,
    reports_root: Path,
    file_path: Path,
    artifact_type: str,
    mime_type: Optional[str],
) -> None:
    """
    Registra un archivo físico como artifact en la tabla artifacts.

    reports_root normalmente será /work/reports.
    El relative_path se calcula relativo a /work para que quede algo como:
      reports/20260313_123000/report.md
    """
    if not file_path.exists() or not file_path.is_file():
        return

    try:
        relative_path = str(file_path.relative_to(reports_root.parent)).replace("\\", "/")
    except Exception:
        relative_path = file_path.name

    db_layer.register_artifact(
        dsn=dsn,
        execution_id=execution_id,
        artifact_type=artifact_type,
        file_name=file_path.name,
        relative_path=relative_path,
        mime_type=mime_type,
        size_bytes=_file_size_or_none(file_path),
    )


# ==========================================================
# SERVICIO PRINCIPAL DE ESCANEO
# ==========================================================

def execute_scan(
    dsn: str,
    workdir: Path,
    url: str,
    timeout_s: int,
    request_source: str = "cli",
) -> Dict[str, Any]:
    """
    Ejecuta una evaluación completa sobre una sola URL y devuelve
    un resumen estructurado del resultado.

    Parámetros:
    - dsn: cadena de conexión PostgreSQL
    - workdir: directorio base de trabajo, normalmente /work
    - url: URL objetivo
    - timeout_s: timeout en segundos para las herramientas
    - request_source: origen de la ejecución ('cli', 'web', 'api')

    Devuelve un diccionario con información útil para:
    - CLI
    - API
    - GUI web

    En éxito:
      {
        "ok": True,
        "execution_id": ...,
        "status": "finished",
        "target_url": ...,
        "report_dir": ...,
        "report_md": ...,
        "report_html": ...,
        "compliance_pct": ...,
        "hsecscan_rc": ...,
        "dalfox_rc": ...,
        "findings_count": ...
      }

    En error:
      {
        "ok": False,
        "execution_id": ...,
        "status": "failed",
        "target_url": ...,
        "report_dir": ...,
        "error": ...
      }
    """
    started = utc_now()

    # ------------------------------------------------------
    # Preparar directorios de salida
    # ------------------------------------------------------
    reports_root = workdir / "reports"
    ensure_dir(reports_root)

    run_id = ts_folder(started)
    report_dir = reports_root / run_id
    ensure_dir(report_dir)

    report_dir_logical = f"/work/reports/{run_id}"

    # ------------------------------------------------------
    # Metadatos iniciales de ejecución
    # ------------------------------------------------------
    run_meta: Dict[str, Any] = {
        "target_url": url,
        "started_at": started.isoformat(),
        "finished_at": None,
        "status": "initiated",
        "execution_id": None,
        "request_source": request_source,
        "errors": [],
        "report_dir": report_dir_logical,
        "artifacts": [],
    }

    # ------------------------------------------------------
    # Insertar ejecución en la base de datos
    # ------------------------------------------------------
    execution_id = db_layer.insert_execution(
        dsn=dsn,
        target_url=url,
        request_source=request_source,
        report_dir=report_dir_logical,
        status="initiated",
        urls_ingresadas=1,
        urls_evaluadas=0,
    )
    run_meta["execution_id"] = execution_id

    run_meta_path = report_dir / RUN_META_JSON
    write_json(run_meta_path, run_meta)

    try:
        # --------------------------------------------------
        # Marcar como running
        # --------------------------------------------------
        db_layer.update_execution_running(dsn, execution_id)
        run_meta["status"] = "running"
        write_json(run_meta_path, run_meta)

        # --------------------------------------------------
        # CAPA 1: curl custom
        # --------------------------------------------------
        raw_last_block, raw_headers_json = curl_fetch_headers(url, timeout_s)
        hdr_eval = evaluate_headers_and_cookies(raw_headers_json)

        headers_json_path = report_dir / HEADERS_JSON
        write_json(
            headers_json_path,
            {
                "target_url": url,
                "evaluation": hdr_eval,
                "raw": raw_headers_json,
                "raw_last_block": raw_last_block,
            },
        )

        db_layer.insert_header_results(
            dsn=dsn,
            execution_id=execution_id,
            hdr_eval=hdr_eval,
            raw_headers_json=raw_headers_json,
        )

        # --------------------------------------------------
        # CAPA 2: hsecscan
        # --------------------------------------------------
        hsecscan_rc, hsecscan_out = run_hsecscan(url)
        hsecscan_txt_path = report_dir / HSECSCAN_TXT
        hsecscan_txt_path.write_text(hsecscan_out, encoding="utf-8", errors="replace")

        db_layer.insert_hsecscan_results(
            dsn=dsn,
            execution_id=execution_id,
            tool_rc=hsecscan_rc,
            raw_output=hsecscan_out,
        )

        # --------------------------------------------------
        # CAPA 3: Dalfox
        # --------------------------------------------------
        dalfox_json_path = report_dir / DALFOX_JSON
        dalfox_rc, dalfox_raw = run_dalfox(url, timeout_s, dalfox_json_path)

        dalfox_txt_path = report_dir / DALFOX_TXT
        dalfox_txt_path.write_text(dalfox_raw, encoding="utf-8", errors="replace")

        findings_count, summary_json = read_summary(dalfox_json_path)

        db_layer.insert_xss_results(
            dsn=dsn,
            execution_id=execution_id,
            tool_rc=dalfox_rc,
            findings_count=findings_count,
            summary_json=summary_json,
            raw_output=safe_read_text(dalfox_txt_path),
        )

        # --------------------------------------------------
        # Generar reportes principales
        # --------------------------------------------------
        report_md = build_report_md(
            target_url=url,
            report_dir=report_dir,
            hdr_eval=hdr_eval,
            hsecscan_filename=HSECSCAN_TXT,
            dalfox_json_filename=DALFOX_JSON,
            dalfox_txt_filename=DALFOX_TXT,
        )

        report_md_path = report_dir / REPORT_MD
        report_md_path.write_text(report_md, encoding="utf-8", errors="replace")

        report_html = build_report_html(
            target_url=url,
            report_dir=report_dir,
            hdr_eval=hdr_eval,
            hsecscan_filename=HSECSCAN_TXT,
            dalfox_json_filename=DALFOX_JSON,
            dalfox_txt_filename=DALFOX_TXT,
        )

        report_html_path = report_dir / REPORT_HTML
        report_html_path.write_text(report_html, encoding="utf-8", errors="replace")

        # --------------------------------------------------
        # Registrar artifacts
        # --------------------------------------------------
        artifact_specs = [
            (headers_json_path, ARTIFACT_TYPE_HEADERS_JSON, MIME_APPLICATION_JSON),
            (hsecscan_txt_path, ARTIFACT_TYPE_HSECSCAN_TXT, MIME_TEXT_PLAIN),
            (dalfox_json_path, ARTIFACT_TYPE_DALFOX_JSON, MIME_APPLICATION_JSON),
            (dalfox_txt_path, ARTIFACT_TYPE_DALFOX_TXT, MIME_TEXT_PLAIN),
            (report_md_path, ARTIFACT_TYPE_REPORT_MD, MIME_TEXT_MARKDOWN),
            (report_html_path, ARTIFACT_TYPE_REPORT_HTML, MIME_TEXT_HTML),
        ]

        for file_path, artifact_type, mime_type in artifact_specs:
            _register_file_artifact(
                dsn=dsn,
                execution_id=execution_id,
                reports_root=reports_root,
                file_path=file_path,
                artifact_type=artifact_type,
                mime_type=mime_type,
            )
            if file_path.exists():
                run_meta["artifacts"].append(file_path.name)

        # --------------------------------------------------
        # Cierre exitoso
        # --------------------------------------------------
        db_layer.update_execution_finished(
            dsn=dsn,
            execution_id=execution_id,
            ok=True,
            error_message=None,
            urls_evaluadas=1,
        )

        finished = utc_now()
        run_meta["finished_at"] = finished.isoformat()
        run_meta["status"] = "finished"
        run_meta["cumplimiento_pct"] = hdr_eval.get("cumplimiento_pct")
        run_meta["hsecscan_rc"] = hsecscan_rc
        run_meta["dalfox_rc"] = dalfox_rc
        run_meta["findings_count"] = findings_count

        write_json(run_meta_path, run_meta)

        _register_file_artifact(
            dsn=dsn,
            execution_id=execution_id,
            reports_root=reports_root,
            file_path=run_meta_path,
            artifact_type=ARTIFACT_TYPE_RUN_META_JSON,
            mime_type=MIME_APPLICATION_JSON,
        )
        if RUN_META_JSON not in run_meta["artifacts"]:
            run_meta["artifacts"].append(RUN_META_JSON)
            write_json(run_meta_path, run_meta)

        return {
            "ok": True,
            "execution_id": execution_id,
            "status": "finished",
            "target_url": url,
            "request_source": request_source,
            "report_dir": report_dir_logical,
            "report_md": f"{report_dir_logical}/{REPORT_MD}",
            "report_html": f"{report_dir_logical}/{REPORT_HTML}",
            "compliance_pct": hdr_eval.get("cumplimiento_pct"),
            "hsecscan_rc": hsecscan_rc,
            "dalfox_rc": dalfox_rc,
            "findings_count": findings_count,
            "artifacts": run_meta["artifacts"],
        }

    except Exception as exc:
        # --------------------------------------------------
        # Manejo de error controlado
        # --------------------------------------------------
        err = str(exc)
        finished = utc_now()

        run_meta["status"] = "failed"
        run_meta["finished_at"] = finished.isoformat()
        run_meta["errors"].append(err)

        write_json(run_meta_path, run_meta)

        try:
            db_layer.update_execution_finished(
                dsn=dsn,
                execution_id=execution_id,
                ok=False,
                error_message=err[:8000],
                urls_evaluadas=0,
            )

            _register_file_artifact(
                dsn=dsn,
                execution_id=execution_id,
                reports_root=reports_root,
                file_path=run_meta_path,
                artifact_type=ARTIFACT_TYPE_RUN_META_JSON,
                mime_type=MIME_APPLICATION_JSON,
            )
        except Exception:
            # Evita encadenar errores durante el manejo de fallos
            pass

        return {
            "ok": False,
            "execution_id": execution_id,
            "status": "failed",
            "target_url": url,
            "request_source": request_source,
            "report_dir": report_dir_logical,
            "error": err,
            "artifacts": run_meta.get("artifacts", []),
        }