import json, os, re, time, argparse
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader
import plotly.graph_objs as go
import plotly.io as pio

# ---------- argparse ----------
def parse_args():
    p = argparse.ArgumentParser(description="Build HTML report from scanner & mapper outputs")
    p.add_argument("--scanner", default="data/scan_results_raw.json", help="Path to scanner JSON")
    p.add_argument("--mapper",  default="data/mapper_final_results.json", help="Path to mapper JSON")
    p.add_argument("--out",     default="out/report.html", help="Output HTML path")
    p.add_argument("--png",     default="out/report.png", help="Output PNG screenshot path")
    # 템플릿은 단일 경로로 받습니다. (예: reporting/report_template.html)
    p.add_argument("--template", default="", help="Path to Jinja2 template (optional)")
    p.add_argument("--no-png", action="store_true", help="Skip PNG screenshot (useful in CI)")
    return p.parse_args()

# ---------- 템플릿 경로 선택 ----------
def resolve_template_path(cli_template: str) -> Path:
    # 1) CLI에서 명시되면 그 파일 우선
    if cli_template:
        tp = Path(cli_template)
        if tp.exists():
            return tp
    # 2) 레포 내 관습 파일명 2종 중 존재하는 쪽 사용
    candidates = [
        Path("reporting/report_template.html"),  # 올바른 철자
        Path("reporting/report_templete.html"),  # 레포에 종종 있는 오탈자 버전
    ]
    for c in candidates:
        if c.exists():
            return c
    raise FileNotFoundError("reporting/ 경로에서 report template(html)을 찾을 수 없습니다.")

# ---------- 로드/정규화 ----------
def load_scanner(path):
    raw = json.loads(Path(path).read_text(encoding="utf-8"))

    # rows 추출: dict(results|scans|raw array) 모두 대응
    if isinstance(raw, list):
        rows = raw
    elif isinstance(raw, dict):
        rows = raw.get("results")
        if rows is None:
            rows = raw.get("scans", raw)
    else:
        raise ValueError(f"[scanner JSON] unexpected type: {type(raw)}")

    open_rows = []
    for r in rows:
        # 키 이름이 달라도 최대한 유연하게 추출
        target = r.get("target") or r.get("ip") or r.get("host")
        port   = r.get("port") or r.get("dst_port") or r.get("service_port")
        state  = (r.get("state") or r.get("status") or "").lower()
        banner = r.get("banner") or r.get("service") or ""
        if target and port and state == "open":
            open_rows.append((target, int(port), banner))
    return open_rows

def load_mapper(path):
    p = Path(path)
    if not p.exists():
        return {}
    data = json.loads(p.read_text(encoding="utf-8"))
    # 기대 스키마: key = "ip:port"
    # 그대로 dict를 넘기면 normalize에서 사용
    return data

def normalize(scanner_open, mapper_dict):
    PORT_NAME = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",
                 143:"imap",389:"ldap",443:"https",445:"smb",1433:"mssql",1521:"oracle",
                 27017:"mongodb",3306:"mysql",3389:"rdp",5432:"postgres",6379:"redis",
                 8080:"http-proxy",8443:"https-alt"}
    def guess(port,banner):
        name = PORT_NAME.get(port,""); ver=""
        if banner:
            m = re.search(r'([0-9]+(?:\.[0-9]+)+)', str(banner))
            if m: ver = m.group(1)
            prod = str(banner).split('/')[0].split()[0].lower()
            if prod and prod not in ("http","https") and len(prod)>=3:
                name = prod
        return name,ver

    hosts = defaultdict(lambda: {"host": None, "ip": None, "open_ports": []})
    now = datetime.now(timezone.utc).isoformat()

    for ip, port, banner in scanner_open:
        key = f"{ip}:{port}"
        mapped = mapper_dict.get(key) if isinstance(mapper_dict, dict) else None
        sname, sver = guess(port, banner)
        cves = []
        if mapped:
            for v in mapped.get("vulnerabilities", []):
                cves.append({
                    "id":   v.get("cve_id"),
                    "cvss": float(v.get("cvss_score", 0.0) or 0.0),
                    "epss": float(v.get("epss_percentile", 0.0) or 0.0),
                    "desc": v.get("description","") or ""
                })
        if hosts[ip]["ip"] is None:
            hosts[ip]["ip"] = ip
        hosts[ip]["open_ports"].append({
            "port": port, "proto": "tcp", "service": sname,
            "banner": (sname+" "+sver).strip() or (banner or ""),
            "cves": cves
        })

    normalized = []
    for ip, h in hosts.items():
        max_host = 0.0
        for p in h["open_ports"]:
            for c in p["cves"]:
                max_host = max(max_host, float(c.get("cvss", 0.0) or 0.0))
        label = "critical" if max_host>=9 else "high" if max_host>=7 else "medium" if max_host>=4 else "low" if max_host>0 else "info"
        h["risk_score"]=round(max_host,2); h["risk_label"]=label; h["last_scan"]=now
        normalized.append(h)
    return normalized

# ---------- 차트 ----------
def mk_charts(hosts):
    sev = Counter([h["risk_label"] for h in hosts])
    fig1 = go.Figure(data=[go.Pie(labels=list(sev.keys()), values=list(sev.values()), hole=0.3)])
    pie_html = pio.to_html(fig1, full_html=False, include_plotlyjs='cdn')

    pc = Counter()
    for h in hosts:
        for p in h["open_ports"]:
            pc[p["port"]]+=1
    top = pc.most_common(10)
    xs,ys = ([],[]) if not top else zip(*top)
    fig2 = go.Figure(data=[go.Bar(x=list(xs), y=list(ys))])
    bar_html = pio.to_html(fig2, full_html=False, include_plotlyjs=False)

    cc = Counter()
    for h in hosts:
        for p in h["open_ports"]:
            for c in p["cves"]:
                if c.get("id"): cc[c["id"]]+=1
    topc = cc.most_common(10)
    xs2,ys2 = ([],[]) if not topc else zip(*topc)
    fig3 = go.Figure(data=[go.Bar(x=list(xs2), y=list(ys2))])
    cve_html = pio.to_html(fig3, full_html=False, include_plotlyjs=False)

    return {"pie":pie_html,"bar":bar_html,"cve":cve_html}

# ---------- 렌더 ----------
def render(hosts, template_path: Path, out_html: Path):
    env = Environment(loader=FileSystemLoader(str(template_path.parent)))
    tpl = env.get_template(template_path.name)
    summary = {"hosts":len(hosts),"total_ports":sum(len(h["open_ports"]) for h in hosts)}
    charts = mk_charts(hosts)
    html = tpl.render(summary=summary, charts=charts, data=hosts, generated_at=datetime.utcnow().isoformat()+"Z")
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text(html, encoding="utf-8")
    print("Wrote", out_html)

# ---------- 캡쳐 ----------
def capture_png(out_html: Path, out_png: Path):
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        opt = Options(); opt.add_argument("--headless=new"); opt.add_argument("--disable-gpu"); opt.add_argument("--window-size=1920,2000")
        d = webdriver.Chrome(options=opt)
        d.get("file://" + str(out_html.resolve()))
        time.sleep(1.0)
        h = d.execute_script("return Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)")
        d.set_window_size(1920, int(h)+100); time.sleep(0.5)
        d.save_screenshot(str(out_png)); d.quit()
        print("Saved", out_png)
    except Exception as e:
        print("Screenshot skipped:", e)

# ---------- main ----------
if __name__ == "__main__":
    args = parse_args()
    scanner_path = Path(args.scanner)
    mapper_path  = Path(args.mapper)
    out_html     = Path(args.out)
    out_png      = Path(args.png)

    # 존재 확인 + 친절한 에러
    if not scanner_path.exists():
        raise FileNotFoundError(f"Scanner JSON not found: {scanner_path}")
    if mapper_path and not mapper_path.exists():
        print(f"[warn] Mapper JSON not found, continuing without: {mapper_path}")

    scanner_open = load_scanner(scanner_path)
    mapper_dict  = load_mapper(mapper_path)

    template_path = resolve_template_path(args.template)
    hosts = normalize(scanner_open, mapper_dict)
    render(hosts, template_path, out_html)

    if not args.no_png:
        capture_png(out_html, out_png)
