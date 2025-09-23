#!/usr/bin/env python3
import time, sqlite3, subprocess, os, sys
ROOT = os.path.dirname(os.path.dirname(__file__)) if __file__ else "."
DB = os.path.join(ROOT, "assets.db")
SCAN_RUNNER = os.path.join(ROOT, "scripts", "scan_runner.py")
PARSER = os.path.join(ROOT, "scripts", "nmap_parser.py")

def init_jobs():
    conn=sqlite3.connect(DB)
    cur=conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, profile TEXT, status TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.commit(); conn.close()

def enqueue(target, profile="safe_operational"):
    conn=sqlite3.connect(DB); cur=conn.cursor()
    cur.execute("INSERT INTO jobs (target,profile,status) VALUES (?,?,?)",(target,profile,"queued"))
    conn.commit(); conn.close()

def fetch_job():
    conn=sqlite3.connect(DB); cur=conn.cursor()
    cur.execute("SELECT id,target,profile FROM jobs WHERE status='queued' ORDER BY created_at LIMIT 1")
    row=cur.fetchone(); conn.close(); return row

def mark_job(id,status):
    conn=sqlite3.connect(DB); cur=conn.cursor()
    cur.execute("UPDATE jobs SET status=? WHERE id=?",(status,id)); conn.commit(); conn.close()

def run_job(profile,target, run_real=False):
    cmd=["python", SCAN_RUNNER, profile, target]
    if run_real: cmd.append("--run")
    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=False)
    # parse latest xml
    outdir=os.path.join(ROOT,"nmap_outputs")
    files=sorted([os.path.join(outdir,f) for f in os.listdir(outdir)], key=os.path.getmtime, reverse=True)
    if files:
        latest=files[0]
        subprocess.run(["python", PARSER, latest], check=False)
        return latest
    return None

def main(poll=5, run_real=False):
    init_jobs()
    print("Worker started. Poll interval:", poll)
    try:
        while True:
            job=fetch_job()
            if job:
                jid, target, profile = job
                print("Picked job:", jid, target, profile)
                mark_job(jid,"running")
                try:
                    xml = run_job(profile,target, run_real=run_real)
                    mark_job(jid,"done")
                    print("Job finished, xml:", xml)
                except Exception as e:
                    mark_job(jid,"failed")
                    print("Job failed:", e)
            time.sleep(poll)
    except KeyboardInterrupt:
        print("Stopping worker")

if __name__ == "__main__":
    run_real = ("--run" in sys.argv)
    interval = 5
    main(poll=interval, run_real=run_real)
