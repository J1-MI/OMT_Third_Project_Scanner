#!/usr/bin/env python3
import os

NMAP_BIN = os.getenv("NMAP_BIN", "nmap")  # 기본은 그냥 'nmap'

import sqlite3, yaml, shlex, subprocess, datetime, os, sys
ROOT = os.path.dirname(os.path.dirname(__file__)) if __file__ else "."
DB = os.path.join(ROOT, "assets.db")
PROFILES = os.path.join(ROOT, "scripts", "scan_profiles.yaml")
OUTDIR = os.path.join(ROOT, "nmap_outputs")
os.makedirs(OUTDIR, exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS scan_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        profile_name TEXT,
        target TEXT,
        nmap_cmd TEXT,
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        finished_at TIMESTAMP,
        status TEXT,
        initiated_by TEXT,
        notes TEXT
    )""")
    conn.commit()
    return conn

def load_profiles():
    with open(PROFILES,"r",encoding="utf-8") as f:
        return yaml.safe_load(f)["profiles"]

def build_nmap_cmd(profile_def, target):
    flags = profile_def.get("nmap_flags", [])
    timing = profile_def.get("timing_template","")
    port_range = profile_def.get("port_range","1-1024")
    min_rate = profile_def.get("min_rate")
    max_rate = profile_def.get("max_rate")
    safe_mode = profile_def.get("safe_mode",True)
    out_xml = os.path.join(OUTDIR, f"nmap_{int(datetime.datetime.utcnow().timestamp())}.xml")
    cmd = [NMAP_BIN]

    if timing:
        cmd.append(timing)
    cmd += flags
    if "-p" not in flags:
        cmd += ["-p", port_range]
    if min_rate:
        cmd += ["--min-rate", str(min_rate)]
    if max_rate:
        cmd += ["--max-rate", str(max_rate)]
    if safe_mode:
        cmd = [c for c in cmd if not (isinstance(c,str) and "--script=vuln" in c)]
    cmd += ["-oX", out_xml, target]
    return cmd, out_xml

def create_scan_run(conn, profile, target, nmap_cmd, user):
    cur = conn.cursor()
    cur.execute("INSERT INTO scan_runs(profile_name,target,nmap_cmd,status,initiated_by) VALUES (?,?,?,?,?)",
                (profile,target,nmap_cmd,"queued",user))
    conn.commit()
    return cur.lastrowid

def update_scan_run(conn, run_id, status, notes=None):
    cur=conn.cursor()
    cur.execute("UPDATE scan_runs SET status=?, finished_at=CURRENT_TIMESTAMP, notes=? WHERE id=?", (status, notes, run_id))
    conn.commit()

def run_scan(profile_name, target, user="operator", dry_run=True):
    profiles = load_profiles()
    if profile_name not in profiles:
        raise ValueError("Unknown profile")
    profile = profiles[profile_name]
    cmd_list, out_xml = build_nmap_cmd(profile, target)
    nmap_cmd = " ".join(shlex.quote(x) for x in cmd_list)
    conn = init_db()
    run_id = create_scan_run(conn, profile_name, target, nmap_cmd, user)
    update_scan_run(conn, run_id, "running")
    try:
        if dry_run:
            print("[DRY RUN] ", nmap_cmd)
            update_scan_run(conn, run_id, "success", notes="dry-run")
            return run_id, out_xml
        subprocess.run(cmd_list, check=True)
        update_scan_run(conn, run_id, "success")
    except Exception as e:
        update_scan_run(conn, run_id, "failure", notes=str(e))
        raise
    finally:
        conn.close()
    return run_id, out_xml

if __name__ == "__main__":
    if len(sys.argv)<3:
        print("Usage: python scripts/scan_runner.py <profile> <target> [--run]")
        sys.exit(1)
    profile = sys.argv[1]; target=sys.argv[2]
    do_run = ("--run" in sys.argv)
    run_scan(profile, target, dry_run=not do_run)
