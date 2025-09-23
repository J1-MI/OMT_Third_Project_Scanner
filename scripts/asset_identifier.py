#!/usr/bin/env python3
"""
asset_identifier.py
- Resolve domains/IPs, classify EXTERNAL/INTERNAL/MIXED/UNRESOLVED
- Persist into assets table in assets.db

Usage:
  python scripts/asset_identifier.py --single example.com
  python scripts/asset_identifier.py --input domains.txt
  python scripts/asset_identifier.py --show-db
"""
import argparse, sqlite3, socket, json, ipaddress, os
from datetime import datetime

# try dnspython
try:
    import dns.resolver, dns.reversename
    DNSPY=True
except Exception:
    DNSPY=False

ROOT = os.path.dirname(os.path.dirname(__file__)) if __file__ else "."
DB = os.path.join(ROOT, "assets.db")

# DB init
def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS assets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subject TEXT,
      subject_type TEXT,
      tag TEXT,
      meta TEXT,
      last_seen TIMESTAMP
    )""")
    conn.commit()
    return conn

def reverse_dns(ip):
    try:
        if DNSPY:
            rev = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev, "PTR", lifetime=3)
            return answers[0].to_text().rstrip(".")
        else:
            return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def is_private_ip(ip):
    try:
        ipobj = ipaddress.ip_address(ip)
        return ipobj.is_private or ipobj.is_loopback or ipobj.is_link_local or ipobj.is_reserved or ipobj.is_unspecified
    except Exception:
        return False

def resolve_basic(domain):
    # fallback using socket
    results = {"A":[],"AAAA":[],"CNAME":[]}
    try:
        infos = socket.getaddrinfo(domain, None)
        for fam, st, proto, canon, sockaddr in infos:
            ip = sockaddr[0]
            if ":" in ip:
                results["AAAA"].append(ip)
            else:
                results["A"].append(ip)
    except Exception:
        pass
    return results

def resolve_dns(domain):
    res = {"A":[],"AAAA":[],"CNAME":[]}
    if DNSPY:
        r = dns.resolver.Resolver()
        for t in ("A","AAAA","CNAME"):
            try:
                answers = r.resolve(domain, t, lifetime=3)
                for a in answers:
                    res[t].append(a.to_text())
            except Exception:
                pass
    else:
        res = resolve_basic(domain)
    return res

def classify_domain(ips):
    public = sum(0 for ip in ips if not is_private_ip(ip))
    private = sum(0 for ip in ips if is_private_ip(ip))
    if not ips:
        return "UNRESOLVED"
    if public>0 and private==0:
        return "EXTERNAL"
    if private>0 and public==0:
        return "INTERNAL"
    return "MIXED"

def upsert_asset(conn, subject, subject_type, tag, meta):
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute("INSERT INTO assets(subject,subject_type,tag,meta,last_seen) VALUES (?,?,?,?,?)",
                (subject, subject_type, tag, json.dumps(meta), now))
    conn.commit()

def process_domain(conn, domain):
    domain = domain.strip()
    res = resolve_dns(domain)
    ips = []
    for t in ("A","AAAA"):
        for ip in res.get(t,[]):
            if ip not in ips:
                ips.append(ip)
    # follow CNAMEs
    for cname in res.get("CNAME",[]):
        cname = cname.rstrip(".")
        cres = resolve_dns(cname)
        for t in ("A","AAAA"):
            for ip in cres.get(t,[]):
                if ip not in ips:
                    ips.append(ip)
    rdns_map = {ip: reverse_dns(ip) for ip in ips}
    tag = classify_domain(ips)
    meta = {"ips": ips, "rdns": rdns_map}
    upsert_asset(conn, domain, "domain", tag, meta)
    return {"domain":domain,"tag":tag,"meta":meta}

def process_ip(conn, ip):
    rdns = reverse_dns(ip)
    tag = "EXTERNAL" if not is_private_ip(ip) else "INTERNAL"
    meta = {"ip":ip,"rdns":rdns}
    upsert_asset(conn, ip, "ip", tag, meta)
    return {"ip":ip,"tag":tag,"meta":meta}

def show_db(conn, limit=200):
    cur = conn.cursor()
    cur.execute("SELECT id,subject,subject_type,tag,last_seen,meta FROM assets ORDER BY last_seen DESC LIMIT ?", (limit,))
    for r in cur.fetchall():
        id_, subject, stype, tag, last_seen, meta = r
        print(f"[{id_}] {stype} {subject} -> {tag} ({last_seen})")
        try:
            print("   meta:", json.dumps(json.loads(meta), ensure_ascii=False, indent=2))
        except:
            print("   meta:", meta)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", help="file with domains (one per line)")
    parser.add_argument("--single", help="single domain or ip")
    parser.add_argument("--show-db", action="store_true")
    args = parser.parse_args()

    conn = init_db()
    if args.input:
        with open(args.input,"r",encoding="utf-8") as f:
            for line in f:
                line=line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    ipaddress.ip_address(line)
                    print(process_ip(conn,line))
                except Exception:
                    print(process_domain(conn,line))
    elif args.single:
        s=args.single.strip()
        try:
            ipaddress.ip_address(s)
            print(process_ip(conn,s))
        except Exception:
            print(process_domain(conn,s))
    elif args.show_db:
        show_db(conn)
    else:
        parser.print_help()
