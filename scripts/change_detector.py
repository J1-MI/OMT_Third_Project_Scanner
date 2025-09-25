#!/usr/bin/env python3
import sqlite3, os
ROOT = os.path.dirname(os.path.dirname(__file__)) if __file__ else "."
DB = os.path.join(ROOT,"assets.db")

def detect_new_ports(prev_snapshot_table="ports_prev"):
    conn=sqlite3.connect(DB); cur=conn.cursor()
    # create snapshot if not exist
    cur.execute("""CREATE TABLE IF NOT EXISTS ports_prev AS SELECT * FROM ports WHERE 0""")
    # find new entries
    cur.execute("""SELECT p.* FROM ports p LEFT JOIN ports_prev pp ON (p.host_id=pp.host_id AND p.port=pp.port) WHERE pp.id IS NULL""")
    rows=cur.fetchall()
    # refresh snapshot
    cur.execute("DELETE FROM ports_prev")
    cur.execute("INSERT INTO ports_prev SELECT * FROM ports")
    conn.commit(); conn.close()
    return rows

if __name__ == "__main__":
    new = detect_new_ports()
    if new:
        print("New ports detected:", len(new))
        for r in new[:10]:
            print(r)
    else:
        print("No new ports")
