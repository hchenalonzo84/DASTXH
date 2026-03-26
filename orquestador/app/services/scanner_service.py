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


- Servicio reutilizable para ejecutar una evaluación completa DASTXH.
- Ahora queda dividido en dos formas de uso:

  1) execute_scan(...)
     -> ejecución síncrona
     -> útil para CLI o para procesos internos que quieran esperar
        hasta el final del escaneo.

  2) start_scan_in_background(...)
     -> crea la ejecución y lanza el pipeline en segundo plano
     -> útil para GUI web y API, donde NO queremos que el escaneo
        dependa del ciclo de vida de una sola petición HTTP.

Objetivo de esta refactorización:
- desacoplar el pipeline del POST web
- permitir que el navegador cambie de vista sin interrumpir
  la ejecución del escaneo
- seguir reutilizando la misma lógica desde CLI, web y API
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

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
# CONTEXTO INTERNO DE EJECUCIÓN
# ==========================================================

@dataclass
class ScanContext:
    """
    Estructura interna que agrupa los datos mínimos necesarios
    para ejecutar el pipeline sin depender directamente del request web.

    Esto ayuda a:
    - mantener el código más legible
    - reutilizar el mismo pipeline en modo síncrono y en background
    - evitar pasar demasiados parámetros sueltos entre funciones
    """
    execution_id: int
    target_url: str
    request_source: str
    started_at: datetime
    reports_root: Path
    report_dir: Path
    report_dir_logical: str
    run_meta_path: Path


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


def _append_artifact_name(run_meta: Dict[str, Any], file_name: str) -> None:
    """
    Agrega un nombre de artifact a run_meta["artifacts"] solo si
    todavía no existe.

    Esto evita duplicados cuando el mismo archivo se registra más
    de una vez durante el cierre del pipeline.
    """
    artifacts = run_meta.setdefault("artifacts", [])
    if file_name and file_name not in artifacts:
        artifacts.append(file_name)


def _build_unique_run_id(reports_root: Path, started: datetime) -> str:
    """
    Genera un identificador de carpeta basado en timestamp.

    Mantiene el formato tradicional YYYYMMDD_HHMMSS y solo agrega
    un sufijo si ya existe una carpeta con ese nombre.

    Esto evita choques si dos ejecuciones se inician en el mismo segundo.
    """
    base_run_id = ts_folder(started)
    candidate = base_run_id
    counter = 1

    while (reports_root / candidate).exists():
        counter += 1
        candidate = f"{base_run_id}_{counter:02d}"

    return candidate


def _prepare_scan_context(
    dsn: str,
    workdir: Path,
    url: str,
    request_source: str,
) -> Tuple[ScanContext, Dict[str, Any]]:
    """
    Prepara toda la estructura mínima de una nueva ejecución,
    pero todavía NO ejecuta el pipeline.

    Aquí se hace:
    - creación de carpetas base
    - creación del directorio de reportes de la ejecución
    - inserción del registro inicial en PostgreSQL
    - generación del archivo run_meta.json inicial

    Esta separación es la clave para poder:
    - correr el pipeline de forma síncrona
    - o lanzarlo en segundo plano desde la GUI/API
    """
    started = utc_now()

    # ------------------------------------------------------
    # Preparar directorios base
    # ------------------------------------------------------
    ensure_dir(workdir)

    reports_root = workdir / "reports"
    ensure_dir(reports_root)

    # ------------------------------------------------------
    # Crear carpeta física única para la ejecución
    # ------------------------------------------------------
    run_id = _build_unique_run_id(reports_root, started)
    report_dir = reports_root / run_id
    ensure_dir(report_dir)

    report_dir_logical = f"/work/reports/{run_id}"

    # ------------------------------------------------------
    # Insertar ejecución inicial en la base de datos
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

    # ------------------------------------------------------
    # Construir contexto reusable del pipeline
    # ------------------------------------------------------
    context = ScanContext(
        execution_id=execution_id,
        target_url=url,
        request_source=request_source,
        started_at=started,
        reports_root=reports_root,
        report_dir=report_dir,
        report_dir_logical=report_dir_logical,
        run_meta_path=report_dir / RUN_META_JSON,
    )

    # ------------------------------------------------------
    # Crear metadatos iniciales de ejecución
    # ------------------------------------------------------
    run_meta: Dict[str, Any] = {
        "target_url": url,
        "started_at": started.isoformat(),
        "finished_at": None,
        "status": "initiated",
        "execution_id": execution_id,
        "request_source": request_source,
        "errors": [],
        "report_dir": report_dir_logical,
        "artifacts": [],
    }

    write_json(context.run_meta_path, run_meta)

    return context, run_meta


def _run_scan_pipeline(
    dsn: str,
    context: ScanContext,
    timeout_s: int,
    run_meta: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Ejecuta el pipeline completo de evaluación usando un contexto ya preparado.

    Esta función contiene la lógica real del escaneo.
    Se usa tanto para:
    - execute_scan(...)               -> modo síncrono
    - start_scan_in_background(...)   -> modo asíncrono

    De esta forma no duplicamos la lógica principal del pipeline.
    """
    execution_id = context.execution_id
    url = context.target_url
    request_source = context.request_source
    report_dir = context.report_dir
    report_dir_logical = context.report_dir_logical
    reports_root = context.reports_root
    run_meta_path = context.run_meta_path

    try:
        # --------------------------------------------------
        # Marcar ejecución como running
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
        # Registrar artifacts generados durante el pipeline
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
                _append_artifact_name(run_meta, file_path.name)

        # --------------------------------------------------
        # Cierre exitoso de la ejecución
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

        # También registramos el propio run_meta.json como artifact
        _register_file_artifact(
            dsn=dsn,
            execution_id=execution_id,
            reports_root=reports_root,
            file_path=run_meta_path,
            artifact_type=ARTIFACT_TYPE_RUN_META_JSON,
            mime_type=MIME_APPLICATION_JSON,
        )

        _append_artifact_name(run_meta, RUN_META_JSON)
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
        # Manejo de error controlado del pipeline
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

            _append_artifact_name(run_meta, RUN_META_JSON)
            write_json(run_meta_path, run_meta)
        except Exception:
            # Evita encadenar errores adicionales durante el manejo de fallos
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


def _background_scan_worker(
    dsn: str,
    context: ScanContext,
    timeout_s: int,
    run_meta: Dict[str, Any],
) -> None:
    """
    Worker interno que ejecuta el pipeline en segundo plano.

    No devuelve nada porque su función es únicamente correr
    el proceso y dejar trazabilidad en:
    - PostgreSQL
    - run_meta.json
    - artifacts/reportes físicos

    El resultado se consulta después desde la BD o desde
    los endpoints de detalle/historial.
    """
    _run_scan_pipeline(
        dsn=dsn,
        context=context,
        timeout_s=timeout_s,
        run_meta=run_meta,
    )


# ==========================================================
# SERVICIO PÚBLICO: MODO SÍNCRONO
# ==========================================================

def execute_scan(
    dsn: str,
    workdir: Path,
    url: str,
    timeout_s: int,
    request_source: str = "cli",
) -> Dict[str, Any]:
    """
    Ejecuta una evaluación completa de forma síncrona.

    Este método conserva el comportamiento esperado por la CLI:
    - crea la ejecución
    - corre todo el pipeline
    - espera a que termine
    - devuelve el resultado final completo
    """
    context, run_meta = _prepare_scan_context(
        dsn=dsn,
        workdir=workdir,
        url=url,
        request_source=request_source,
    )

    return _run_scan_pipeline(
        dsn=dsn,
        context=context,
        timeout_s=timeout_s,
        run_meta=run_meta,
    )


# ==========================================================
# SERVICIO PÚBLICO: MODO ASÍNCRONO / BACKGROUND
# ==========================================================

def start_scan_in_background(
    dsn: str,
    workdir: Path,
    url: str,
    timeout_s: int,
    request_source: str = "web",
) -> Dict[str, Any]:
    """
    Inicia un escaneo en segundo plano y devuelve inmediatamente
    los datos mínimos de seguimiento.

    Este método es el que necesitaremos usar desde:
    - rutas API POST /api/scans
    - GUI web
    - cualquier flujo donde NO queramos bloquear la respuesta HTTP

    Flujo:
    1) prepara contexto y crea registro en DB
    2) lanza un hilo en background
    3) devuelve rápido execution_id y estado inicial

    Nota:
    - El hilo se marca como daemon=True para no bloquear apagados
      del proceso del servidor.
    - Para un futuro despliegue más robusto, esto podría migrarse
      a una cola de trabajos o worker separado.
    """
    context, run_meta = _prepare_scan_context(
        dsn=dsn,
        workdir=workdir,
        url=url,
        request_source=request_source,
    )

    worker = threading.Thread(
        target=_background_scan_worker,
        kwargs={
            "dsn": dsn,
            "context": context,
            "timeout_s": timeout_s,
            "run_meta": run_meta,
        },
        name=f"dastxh-scan-{context.execution_id}",
        daemon=True,
    )
    worker.start()

    return {
        "ok": True,
        "accepted": True,
        "execution_id": context.execution_id,
        "status": "initiated",
        "target_url": context.target_url,
        "request_source": context.request_source,
        "report_dir": context.report_dir_logical,
    }