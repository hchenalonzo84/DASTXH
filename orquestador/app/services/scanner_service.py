"""
scanner_service.py
- Servicio reutilizable para ejecutar una evaluación completa DASTXH.
- Esta versión queda adaptada al esquema normalizado v4.

Formas de uso:
  1) execute_scan(...)
     -> ejecución síncrona
     -> útil para CLI o flujos internos que esperan el resultado final

  2) start_scan_in_background(...)
     -> crea la ejecución y lanza el pipeline en segundo plano
     -> útil para GUI web y API

Cambios importantes en esta versión:
- se conserva el flujo background ya implementado
- se insertan resultados de headers/cookies en tablas normalizadas
- se extraen hallazgos XSS estructurados desde Dalfox
- se insertan hallazgos XSS en xss_findings
- se soportan scan_profile y enable_hsecscan
- superficial desactiva hsecscan por defecto
- profundo activa hsecscan por defecto
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
from tools.dalfox_tool import extract_structured_findings, read_summary, run_dalfox
from tools.hsecscan_tool import run_hsecscan
from utils import ensure_dir, safe_read_text, ts_folder, utc_now, write_json


# ==========================================================
# CONTEXTO INTERNO DE EJECUCIÓN
# ==========================================================

@dataclass
class ScanContext:
    """
    Estructura interna que agrupa los datos mínimos necesarios
    para ejecutar el pipeline sin depender del request web.
    """
    execution_id: int
    target_url: str
    request_source: str
    started_at: datetime
    reports_root: Path
    report_dir: Path
    report_dir_logical: str
    run_meta_path: Path
    scan_profile: str
    enable_hsecscan: bool


# ==========================================================
# HELPERS INTERNOS
# ==========================================================

def _normalize_scan_profile(scan_profile: Optional[str]) -> str:
    """
    Normaliza el perfil recibido.

    Valores válidos:
    - superficial
    - profundo

    Cualquier otro valor cae en superficial para:
    - evitar errores por input inválido
    - no romper el CHECK de la BD
    """
    value = (scan_profile or "").strip().lower()
    return "profundo" if value == "profundo" else "superficial"


def _resolve_enable_hsecscan(
    scan_profile: str,
    enable_hsecscan: Optional[bool],
) -> bool:
    """
    Resuelve el valor final de enable_hsecscan.

    Regla base pedida:
    - superficial -> False
    - profundo    -> True

    Pero dejamos soporte para override explícito a futuro:
    - si llega enable_hsecscan, ese valor manda
    - si no llega, se deriva del perfil
    """
    if enable_hsecscan is not None:
        return bool(enable_hsecscan)

    return scan_profile == "profundo"


def _file_size_or_none(path: Path) -> Optional[int]:
    """
    Devuelve el tamaño del archivo en bytes si existe.
    Si no existe o falla, devuelve None.
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
    Agrega un artifact al run_meta solo si todavía no existe.
    """
    artifacts = run_meta.setdefault("artifacts", [])
    if file_name and file_name not in artifacts:
        artifacts.append(file_name)


def _build_unique_run_id(reports_root: Path, started: datetime) -> str:
    """
    Genera un identificador de carpeta único basado en timestamp.

    Si ya existe una carpeta con el timestamp base, agrega sufijo.
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
    scan_profile: str = "superficial",
    enable_hsecscan: Optional[bool] = None,
) -> Tuple[ScanContext, Dict[str, Any]]:
    """
    Prepara la estructura mínima de una nueva ejecución, pero
    todavía no ejecuta el pipeline.

    Aquí resolvemos y persistimos desde el inicio:
    - scan_profile
    - enable_hsecscan
    """
    started = utc_now()

    ensure_dir(workdir)

    reports_root = workdir / "reports"
    ensure_dir(reports_root)

    run_id = _build_unique_run_id(reports_root, started)
    report_dir = reports_root / run_id
    ensure_dir(report_dir)

    report_dir_logical = f"/work/reports/{run_id}"

    normalized_scan_profile = _normalize_scan_profile(scan_profile)
    resolved_enable_hsecscan = _resolve_enable_hsecscan(
        scan_profile=normalized_scan_profile,
        enable_hsecscan=enable_hsecscan,
    )

    execution_id = db_layer.insert_execution(
        dsn=dsn,
        target_url=url,
        request_source=request_source,
        report_dir=report_dir_logical,
        status="initiated",
        scan_profile=normalized_scan_profile,
        enable_hsecscan=resolved_enable_hsecscan,
        urls_ingresadas=1,
        urls_evaluadas=0,
    )

    context = ScanContext(
        execution_id=execution_id,
        target_url=url,
        request_source=request_source,
        started_at=started,
        reports_root=reports_root,
        report_dir=report_dir,
        report_dir_logical=report_dir_logical,
        run_meta_path=report_dir / RUN_META_JSON,
        scan_profile=normalized_scan_profile,
        enable_hsecscan=resolved_enable_hsecscan,
    )

    run_meta: Dict[str, Any] = {
        "target_url": url,
        "started_at": started.isoformat(),
        "finished_at": None,
        "status": "initiated",
        "execution_id": execution_id,
        "request_source": request_source,
        "scan_profile": normalized_scan_profile,
        "enable_hsecscan": resolved_enable_hsecscan,
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
    Ejecuta el pipeline completo usando un contexto ya preparado.

    Se usa tanto para:
    - execute_scan(...)
    - start_scan_in_background(...)
    """
    execution_id = context.execution_id
    url = context.target_url
    request_source = context.request_source
    report_dir = context.report_dir
    report_dir_logical = context.report_dir_logical
    reports_root = context.reports_root
    run_meta_path = context.run_meta_path
    scan_profile = context.scan_profile
    enable_hsecscan = context.enable_hsecscan

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
                "scan_profile": scan_profile,
                "enable_hsecscan": enable_hsecscan,
            },
        )

        db_layer.insert_header_results(
            dsn=dsn,
            execution_id=execution_id,
            hdr_eval=hdr_eval,
            raw_headers_json=raw_headers_json,
        )

        # --------------------------------------------------
        # CAPA 2: hsecscan (opcional según perfil)
        # --------------------------------------------------
        hsecscan_rc: Optional[int] = None
        hsecscan_out = ""
        hsecscan_txt_path = report_dir / HSECSCAN_TXT

        if enable_hsecscan:
            hsecscan_rc, hsecscan_out = run_hsecscan(url)
            hsecscan_txt_path.write_text(hsecscan_out, encoding="utf-8", errors="replace")

            db_layer.insert_hsecscan_results(
                dsn=dsn,
                execution_id=execution_id,
                tool_rc=hsecscan_rc,
                raw_output=hsecscan_out,
            )
        else:
            run_meta["hsecscan_skipped"] = True
            run_meta["hsecscan_skip_reason"] = (
                f"La capa 2 fue omitida porque el perfil activo es '{scan_profile}' "
                f"y enable_hsecscan quedó en False."
            )

        # --------------------------------------------------
        # CAPA 3: Dalfox
        # --------------------------------------------------
        dalfox_json_path = report_dir / DALFOX_JSON
        dalfox_rc, dalfox_raw = run_dalfox(
            url=url,
            timeout_s=timeout_s,
            out_json=dalfox_json_path,
            scan_profile=scan_profile,
        )

        dalfox_txt_path = report_dir / DALFOX_TXT
        dalfox_txt_path.write_text(dalfox_raw, encoding="utf-8", errors="replace")

        findings_count, summary_json = read_summary(dalfox_json_path)

        # Extraer hallazgos estructurados para la tabla xss_findings
        structured_findings = extract_structured_findings(
            summary_json=summary_json,
            fallback_target_url=url,
        )
        db_layer.insert_xss_results(
            dsn=dsn,
            execution_id=execution_id,
            tool_rc=dalfox_rc,
            findings_count=findings_count,
            summary_json=summary_json,
            raw_output=safe_read_text(dalfox_txt_path),
            xss_findings=structured_findings,
        )

        # --------------------------------------------------
        # Generar reportes principales
        # --------------------------------------------------
        report_md = build_report_md(
            target_url=url,
            report_dir=report_dir,
            hdr_eval=hdr_eval,
            scan_profile=scan_profile,
            enable_hsecscan=enable_hsecscan,
            hsecscan_filename=HSECSCAN_TXT if enable_hsecscan else None,
            dalfox_json_filename=DALFOX_JSON,
            dalfox_txt_filename=DALFOX_TXT,
        )

        report_md_path = report_dir / REPORT_MD
        report_md_path.write_text(report_md, encoding="utf-8", errors="replace")

        report_html = build_report_html(
            target_url=url,
            report_dir=report_dir,
            hdr_eval=hdr_eval,
            scan_profile=scan_profile,
            enable_hsecscan=enable_hsecscan,
            hsecscan_filename=HSECSCAN_TXT if enable_hsecscan else None,
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
            (dalfox_json_path, ARTIFACT_TYPE_DALFOX_JSON, MIME_APPLICATION_JSON),
            (dalfox_txt_path, ARTIFACT_TYPE_DALFOX_TXT, MIME_TEXT_PLAIN),
            (report_md_path, ARTIFACT_TYPE_REPORT_MD, MIME_TEXT_MARKDOWN),
            (report_html_path, ARTIFACT_TYPE_REPORT_HTML, MIME_TEXT_HTML),
        ]

        # Solo registrar artifact de hsecscan si realmente se ejecutó.
        if enable_hsecscan and hsecscan_txt_path.exists():
            artifact_specs.insert(
                1,
                (hsecscan_txt_path, ARTIFACT_TYPE_HSECSCAN_TXT, MIME_TEXT_PLAIN),
            )

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
        run_meta["scan_profile"] = scan_profile
        run_meta["enable_hsecscan"] = enable_hsecscan
        run_meta["cumplimiento_pct"] = hdr_eval.get("cumplimiento_pct")
        run_meta["hsecscan_rc"] = hsecscan_rc
        run_meta["dalfox_rc"] = dalfox_rc
        run_meta["findings_count"] = findings_count
        run_meta["xss_findings_structured_count"] = len(structured_findings)

        write_json(run_meta_path, run_meta)

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
            "scan_profile": scan_profile,
            "enable_hsecscan": enable_hsecscan,
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
        # Manejo controlado de errores
        # --------------------------------------------------
        err = str(exc)
        finished = utc_now()

        run_meta["status"] = "failed"
        run_meta["finished_at"] = finished.isoformat()
        run_meta["scan_profile"] = scan_profile
        run_meta["enable_hsecscan"] = enable_hsecscan
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
            pass

        return {
            "ok": False,
            "execution_id": execution_id,
            "status": "failed",
            "target_url": url,
            "request_source": request_source,
            "scan_profile": scan_profile,
            "enable_hsecscan": enable_hsecscan,
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
    Worker interno para ejecutar el pipeline en segundo plano.
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
    scan_profile: str = "superficial",
    enable_hsecscan: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Ejecuta una evaluación completa de forma síncrona.

    Nuevos parámetros:
    - scan_profile
    - enable_hsecscan (opcional; si no llega, se deriva del perfil)
    """
    context, run_meta = _prepare_scan_context(
        dsn=dsn,
        workdir=workdir,
        url=url,
        request_source=request_source,
        scan_profile=scan_profile,
        enable_hsecscan=enable_hsecscan,
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
    scan_profile: str = "superficial",
    enable_hsecscan: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Inicia un escaneo en segundo plano y devuelve inmediatamente
    los datos mínimos de seguimiento.

    Reglas por defecto:
    - superficial -> hsecscan desactivado
    - profundo    -> hsecscan activado
    """
    context, run_meta = _prepare_scan_context(
        dsn=dsn,
        workdir=workdir,
        url=url,
        request_source=request_source,
        scan_profile=scan_profile,
        enable_hsecscan=enable_hsecscan,
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
        "scan_profile": context.scan_profile,
        "enable_hsecscan": context.enable_hsecscan,
        "report_dir": context.report_dir_logical,
    }
