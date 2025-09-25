#!/usr/bin/env python3
import sqlite3, xml.etree.ElementTree as ET, os, sys, datetime
ROOT = os.path.dirname(os.path.dirname(__file__)) if __file__ else "."
DB = os.path.join(ROOT, "assets.db")

def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, host_id TEXT UNIQUE, address TEXT, hostname TEXT, state TEXT, last_seen TIMESTAMP
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT, host_id TEXT, port INTEGER, protocol TEXT, state TEXT, service TEXT, product TEXT, version TEXT
    )""")
    conn.commit()
    return conn

def parse_nmap_xml(xmlfile):
    tree = ET.parse(xmlfile)
    root = tree.getroot()
    hosts=[]; ports=[]
    for h in root.findall("host"):
        status = h.find("status")
        state = status.get("state") if status is not None else None
        addr=None
        for a in h.findall("address"):
            at=a.get("addrtype")
            if at in ("ipv4","ipv6"):
                addr=a.get("addr"); break
        hostname=None
        hn=h.find("hostnames")
        if hn is not None:
            hh = hn.find("hostname")
            if hh is not None:
                hostname=hh.get("name")
        hid = addr or hostname or f"host-{len(hosts)}"
        hosts.append({"host_id":hid,"address":addr,"hostname":hostname,"state":state})
        ports_tag=h.find("ports")
        if ports_tag is not None:
            for p in ports_tag.findall("port"):
                portid=int(p.get("portid"))
                proto=p.get("protocol")
                st=p.find("state"); stv = st.get("state") if st is not None else None
                svc=p.find("service")
                svcname = svc.get("name") if svc is not None else None
                prod = svc.get("product") if svc is not None else None
                ver = svc.get("version") if svc is not None else None
                ports.append({"host_id":hid,"port":portid,"protocol":proto,"state":stv,"service":svcname,"product":prod,"version":ver})
    return hosts, ports

def upsert(conn, hosts, ports):
    cur=conn.cursor()
    added={"hosts":0,"ports":0}
    for h in hosts:
        cur.execute("SELECT id FROM hosts WHERE host_id=?", (h["host_id"],))
        row=cur.fetchone()
        now=datetime.datetime.utcnow().isoformat()
        if row:
            cur.execute("UPDATE hosts SET address=?,hostname=?,state=?,last_seen=? WHERE host_id=?",
                        (h["address"],h["hostname"],h["state"],now,h["host_id"]))
        else:
            cur.execute("INSERT INTO hosts (host_id,address,hostname,state,last_seen) VALUES (?,?,?,?,?)",
                        (h["host_id"],h["address"],h["hostname"],h["state"],now))
            added["hosts"]+=1
    # Replace ports for hosts present
    host_ids=set([p["host_id"] for p in ports])
    for hid in host_ids:
        cur.execute("DELETE FROM ports WHERE host_id=?", (hid,))
    for p in ports:
        cur.execute("INSERT INTO ports (host_id,port,protocol,state,service,product,version) VALUES (?,?,?,?,?,?,?)",
                    (p["host_id"],p["port"],p["protocol"],p["state"],p["service"],p["product"],p["version"]))
        added["ports"]+=1
    conn.commit()
    return added

if __name__ == "__main__":
    if len(sys.argv)<2:
        print("Usage: python scripts/nmap_parser.py <nmap_xml_file>")
        sys.exit(1)
    xml=sys.argv[1]
    if not os.path.exists(xml):
        print("XML not found:", xml); sys.exit(1)
    conn=init_db()
    hosts,ports = parse_nmap_xml(xml)
    res = upsert(conn, hosts, ports)
    print("Parsed:", res)
    conn.close()
