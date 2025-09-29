# port_scanner/runners/enrich_runner.py
import json
from pathlib import Path
from port_scanner.plugins.banner_grab import tcp_banner_grab
from port_scanner.plugins.http_enum import enumerate_http
import logging

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
RAW_FILE = DATA_DIR / "scan_results_raw.json"
OUT_FILE = DATA_DIR / "scan_results_enriched.json"

def run_enrichment():
    with RAW_FILE.open("r", encoding="utf-8") as f:
        raw = json.load(f)

    enriched_results = []
    for r in raw.get("results", []):
        ip = r.get("ip") or r.get("target")
        port = r.get("port")
        proto = r.get("proto", "tcp")
        if r.get("state") != "open":
            continue
        # 1) banner grab (if banner absent or to enrich)
        banner = r.get("banner")
        if not banner:
            grabbed = tcp_banner_grab(ip, port)
            if grabbed:
                r["banner"] = grabbed

        # 2) http enum if http-like
        if r.get("service") == "http" or str(port) in ("80","8080","8000","443"):
            try:
                http_info = enumerate_http(ip, port, scheme="http")
                r["enrichment"] = http_info
            except Exception as e:
                logger.exception("http enumerate failed: %s", e)
        enriched_results.append(r)

    out_json = {"generated": raw.get("generated"), "results": enriched_results}
    with OUT_FILE.open("w", encoding="utf-8") as f:
        json.dump(out_json, f, indent=2, ensure_ascii=False)
    print(f"Enrichment finished: wrote {OUT_FILE}")

if __name__ == "__main__":
    run_enrichment()
