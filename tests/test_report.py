import json
from pathlib import Path
import importlib.util

spec = importlib.util.spec_from_file_location(
    "report", str(Path("build_report.py").resolve())
)
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)

def test_load_scanner_accepts_array_schema(tmp_path):
    data = [
        {"target":"1.2.3.4","port":80,"state":"open","banner":"nginx/1.20"},
        {"target":"1.2.3.4","port":22,"state":"closed"}
    ]
    p = tmp_path/"scan.json"; p.write_text(json.dumps(data), encoding="utf-8")
    rows = report.load_scanner(str(p))
    assert rows == [("1.2.3.4",80,"nginx/1.20")]

def test_normalize_risk_labeling():
    scanner = [("1.2.3.4", 80, "nginx/1.20")]
    mapper  = {"1.2.3.4:80":{"vulnerabilities":[{"cve_id":"CVE-X","cvss_score":7.5,"risk_score":7.5}]}}
    hosts = report.normalize(scanner, mapper)
    assert hosts and hosts[0]["risk_label"] in ("high","critical")
