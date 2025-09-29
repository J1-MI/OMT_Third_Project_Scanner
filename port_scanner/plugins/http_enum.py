# port_scanner/plugins/http_enum.py
import requests
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)

COMMON_PATHS = ["/", "/admin", "/manager", "/login", "/upload", "/robots.txt"]

def enumerate_http(ip: str, port: int, scheme: str = "http", timeout: float = 3.0) -> Dict:
    base = f"{scheme}://{ip}:{port}"
    out = {"http_headers": {}, "html_title": None, "paths_found": [], "notes": []}
    try:
        # 헤더 확인
        r = requests.get(base, timeout=timeout, allow_redirects=True)
        out["http_headers"] = dict(r.headers)
        # 타이틀 추출(간단)
        text = r.text
        start = text.find("<title>")
        end = text.find("</title>")
        if start >= 0 and end > start:
            out["html_title"] = text[start+7:end].strip()
    except Exception as e:
        logger.debug("root request failed: %s", e)

    # robots / common paths
    try:
        r = requests.get(base + "/robots.txt", timeout=timeout)
        if r.status_code == 200 and "Disallow" in r.text:
            out["notes"].append("robots.txt available")
            # simple parse for hints
            if "/uploads" in r.text or "/upload" in r.text:
                out["notes"].append("robots suggests upload paths")
    except Exception:
        pass

    # common paths probing (lightweight: HEAD)
    for p in COMMON_PATHS:
        try:
            r = requests.head(base + p, timeout=timeout, allow_redirects=True)
            if r.status_code < 400:
                out["paths_found"].append(p)
        except Exception:
            continue

    return out
