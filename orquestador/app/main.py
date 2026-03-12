"""
main.py
- CLI del prototipo DASTXH.
- Pipeline lineal:
  1) executions initiated
  2) Capa 1: curl custom -> /work + header_results
  3) Capa 2: hsecscan -> /work + hsecscan_results ✅
  4) Capa 3: dalfox -> /work + xss_results
  5) executions finished/failed
  6) report.md + run_meta.json
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import db as db_layer
from config import REPORT_MD, HEADERS_JSON, HSECSCAN_TXT, DALFOX_JSON, DALFOX_TXT, RUN_META_JSON
from report import build_report_md
from tools.curl_custom import curl_fetch_headers, evaluate_headers_and_cookies
from tools.hsecscan_tool import run_hsecscan
from tools.dalfox_tool import run_dalfox, read_summary
from utils import utc_now, ts_folder, ensure_dir, write_json, safe_read_text, load_urls_from_file, wait_for_db


def scan_one(dsn: str, workdir: Path, url: str, timeout_s: int) -> int:
    started = utc_now()
    reports_root = workdir / "reports"
    ensure_dir(reports_root)

    report_dir = reports_root / ts_folder(started)
    ensure_dir(report_dir)

    run_meta = {
        "target_url": url,
        "started_at": started.isoformat(),
        "finished_at": None,
        "status": "initiated",
        "execution_id": None,
        "errors": [],
        "report_dir": f"/work/reports/{report_dir.name}",
    }

    eid = db_layer.insert_execution(dsn, url)
    run_meta["execution_id"] = eid

    try:
        # -------- Capa 1: curl custom --------
        raw_last_block, raw_headers_json = curl_fetch_headers(url, timeout_s)
        hdr_eval = evaluate_headers_and_cookies(raw_headers_json)

        write_json(report_dir / HEADERS_JSON, {
            "target_url": url,
            "evaluation": hdr_eval,
            "raw": raw_headers_json,
            "raw_last_block": raw_last_block,
        })

        db_layer.insert_header_results(dsn, eid, hdr_eval, raw_headers_json)

        # -------- Capa 2: hsecscan (persistir) --------
        hsec_rc, hsec_out = run_hsecscan(url)
        (report_dir / HSECSCAN_TXT).write_text(hsec_out, encoding="utf-8", errors="replace")
        db_layer.insert_hsecscan_results(dsn, eid, hsec_rc, hsec_out)

        # -------- Capa 3: dalfox --------
        dalfox_json_path = report_dir / DALFOX_JSON
        dalfox_rc, dalfox_raw = run_dalfox(url, timeout_s, dalfox_json_path)
        (report_dir / DALFOX_TXT).write_text(dalfox_raw, encoding="utf-8", errors="replace")

        findings_count, summary_json = read_summary(dalfox_json_path)
        db_layer.insert_xss_results(dsn, eid, findings_count, summary_json, safe_read_text(report_dir / DALFOX_TXT))

        # -------- Finalización --------
        db_layer.update_execution_finished(dsn, eid, ok=True)

        report_md = build_report_md(
            target_url=url,
            report_dir=report_dir,
            hdr_eval=hdr_eval,
            hsecscan_filename=HSECSCAN_TXT,
            dalfox_json_filename=DALFOX_JSON,
        )
        (report_dir / REPORT_MD).write_text(report_md, encoding="utf-8")

        finished = utc_now()
        run_meta["finished_at"] = finished.isoformat()
        run_meta["status"] = "finished"
        run_meta["cumplimiento_pct"] = hdr_eval.get("cumplimiento_pct")
        run_meta["hsecscan_rc"] = hsec_rc
        run_meta["dalfox_rc"] = dalfox_rc
        run_meta["findings_count"] = findings_count
        write_json(report_dir / RUN_META_JSON, run_meta)

        print("\n=== DASTXH Summary ===")
        print(f"Execution ID: {eid}")
        print(f"Target:       {url}")
        print(f"Compliance:   {hdr_eval.get('cumplimiento_pct')}%")
        print(f"hsecscan rc:  {hsec_rc}")
        print(f"XSS findings: {findings_count}")
        print(f"Report dir:   /work/reports/{report_dir.name}")
        print(f"Main report:  /work/reports/{report_dir.name}/{REPORT_MD}")
        return 0

    except Exception as e:
        err = str(e)
        run_meta["status"] = "failed"
        run_meta["errors"].append(err)
        run_meta["finished_at"] = utc_now().isoformat()
        write_json(report_dir / RUN_META_JSON, run_meta)

        try:
            db_layer.update_execution_finished(dsn, eid, ok=False, error_message=err[:8000])
        except Exception:
            pass

        print(f"\nERROR: {err}")
        print(f"Reporte parcial: /work/reports/{report_dir.name}")
        return 1


def main() -> int:
    ap = argparse.ArgumentParser(description="DASTXH Orquestador (CLI)")
    ap.add_argument("--url", help="URL objetivo (una sola).", default=None)
    ap.add_argument("--url-file", help="Archivo con URLs (opcional).", default=None)
    ap.add_argument("--timeout", type=int, default=int(os.getenv("DEFAULT_TIMEOUT_SECONDS", "30")))
    args = ap.parse_args()

    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        print("ERROR: DATABASE_URL no está configurada.")
        return 2

    workdir = Path(os.getenv("WORKDIR", "/work"))
    ensure_dir(workdir)

    wait_for_db(lambda: db_layer.ping_db(dsn), timeout_s=40)

    if args.url:
        return scan_one(dsn, workdir, args.url.strip(), args.timeout)

    if args.url_file:
        urls = load_urls_from_file(Path(args.url_file))
        if not urls:
            print("ERROR: url-file no contiene URLs válidas.")
            return 2
        rc = 0
        for u in urls:
            rc = rc or scan_one(dsn, workdir, u, args.timeout)
        return rc

    print("ERROR: Debes usar --url o --url-file")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())