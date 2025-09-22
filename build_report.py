import json, os, re, time
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader
import plotly.graph_objs as go
import plotly.io as pio

SCANNER_JSON = "data/scan_results_raw.json"
MAPPER_JSON  = "data/mapper_final_results.json"
OUT_HTML     = "out/report.html"
OUT_PNG      = "out/report.png"
TEMPLATE_DIR = "reporting"
TEMPLATE_FILE= "report_template.html"
os.makedirs("out", exist_ok=True)

def load_scanner(path):
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = raw.get("results", raw)
    # open 포트만
    return [(r["target"], int(r["port"]), r.get("banner")) for r in rows if r.get("state")=="open"]

def load_mapper(path):
    return json.loads(Path(path).read_text(encoding="utf-8")) if Path(path).exists() else {}

def normalize(scanner_open, mapper_dict):
    PORT_NAME = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",143:"imap",389:"ldap",443:"https",445:"smb",1433:"mssql",1521:"oracle",27017:"mongodb",3306:"mysql",3389:"rdp",5432:"postgres",6379:"redis",8080:"http-proxy",8443:"https-alt"}
    def guess(port,banner):
        name = PORT_NAME.get(port,""); ver=""
        if banner:
            m = re.search(r'([0-9]+(?:\.[0-9]+)+)', banner)
            if m: ver = m.group(1)
            prod = banner.split('/')[0].split()[0].lower()
            if prod and prod not in ("http","https") and len(prod)>=3: name=prod
        return name,ver

    hosts = defaultdict(lambda: {"host": None, "ip": None, "open_ports": []})
    now = datetime.now(timezone.utc).isoformat()

    for ip, port, banner in scanner_open:
        key = f"{ip}:{port}"
        m = mapper_dict.get(key)
        sname, sver = guess(port, banner)
        cves = []
        max_risk_this_port = 0.0
        if m:
            for v in m.get("vulnerabilities", []):
                cves.append({
                    "id": v.get("cve_id"),
                    "cvss": v.get("cvss_score", 0.0),
                    "epss": v.get("epss_percentile", 0.0),
                    "desc": v.get("description","")
                })
                max_risk_this_port = max(max_risk_this_port, float(v.get("risk_score", 0.0)))
        if hosts[ip]["ip"] is None: hosts[ip]["ip"] = ip
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
                max_host = max(max_host, c.get("cvss", 0.0))
        label = "critical" if max_host>=9 else "high" if max_host>=7 else "medium" if max_host>=4 else "low" if max_host>0 else "info"
        h["risk_score"]=round(max_host,2); h["risk_label"]=label; h["last_scan"]=now
        normalized.append(h)
    return normalized

def mk_charts(hosts):
    sev = Counter([h["risk_label"] for h in hosts])
    fig1 = go.Figure(data=[go.Pie(labels=list(sev.keys()), values=list(sev.values()), hole=0.3)])
    pie_html = pio.to_html(fig1, full_html=False, include_plotlyjs='cdn')

    pc = Counter()
    for h in hosts:
        for p in h["open_ports"]:
            pc[p["port"]]+=1
    top = pc.most_common(10); xs,ys = ([],[]) if not top else zip(*top)
    fig2 = go.Figure(data=[go.Bar(x=list(xs), y=list(ys))])
    bar_html = pio.to_html(fig2, full_html=False, include_plotlyjs=False)

    cc = Counter()
    for h in hosts:
        for p in h["open_ports"]:
            for c in p["cves"]:
                if c.get("id"): cc[c["id"]]+=1
    topc = cc.most_common(10); xs2,ys2 = ([],[]) if not topc else zip(*topc)
    fig3 = go.Figure(data=[go.Bar(x=list(xs2), y=list(ys2))])
    cve_html = pio.to_html(fig3, full_html=False, include_plotlyjs=False)

    return {"pie":pie_html,"bar":bar_html,"cve":cve_html}

def render(hosts):
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    tpl = env.get_template(TEMPLATE_FILE)
    summary = {"hosts":len(hosts),"total_ports":sum(len(h["open_ports"]) for h in hosts)}
    charts = mk_charts(hosts)
    html = tpl.render(summary=summary, charts=charts, data=hosts, generated_at=datetime.utcnow().isoformat()+"Z")
    Path(OUT_HTML).write_text(html, encoding="utf-8")
    print("Wrote", OUT_HTML)

def capture_png():
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        opt = Options(); opt.add_argument("--headless=new"); opt.add_argument("--disable-gpu"); opt.add_argument("--window-size=1920,2000")
        d = webdriver.Chrome(options=opt)
        d.get("file://" + os.path.abspath(OUT_HTML))
        time.sleep(1.0)
        h = d.execute_script("return Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)")
        d.set_window_size(1920, h+100); time.sleep(0.5)
        d.save_screenshot(OUT_PNG); d.quit()
        print("Saved", OUT_PNG)
    except Exception as e:
        print("Screenshot skipped:", e)

if __name__ == "__main__":
    scanner_open = load_scanner(SCANNER_JSON)
    mapper_dict  = load_mapper(MAPPER_JSON)
    hosts = normalize(scanner_open, mapper_dict)
    render(hosts)
    capture_png()
