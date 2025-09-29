#!/usr/bin/env python3
import sys, json
from pathlib import Path

"""
Usage:
  python scripts/add_mapping_from_banner.py <ip> <port> <cve_id> "<description>" [cvss_score]

This adds/overwrites an entry in data/mapper_final_results.json with the given CVE.
"""
if len(sys.argv) < 5:
    print("usage: add_mapping_from_banner.py <ip> <port> <cve_id> \"<desc>\" [cvss_score]")
    sys.exit(1)

ip = sys.argv[1]
port = sys.argv[2]
cve = sys.argv[3]
desc = sys.argv[4]
try:
    cvss = float(sys.argv[5]) if len(sys.argv) > 5 else 7.0
except:
    cvss = 7.0

p = Path("data/mapper_final_results.json")
data = {}
if p.exists():
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        data = {}

key = f"{ip}:{port}"
data[key] = {
    "vulnerabilities": [
        {
            "cve_id": cve,
            "cvss_score": cvss,
            "epss_percentile": 0.0,
            "risk_score": cvss,
            "description": desc
        }
    ]
}
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(json.dumps(data, indent=2), encoding="utf-8")
print("Wrote mapping for", key)
