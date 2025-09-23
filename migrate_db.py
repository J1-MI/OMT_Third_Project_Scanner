# migrate_db.py
import sqlite3
sql = open("migrate_scan_tables.sql", "r", encoding="utf-8").read()
conn = sqlite3.connect("assets.db")
conn.executescript(sql)
conn.commit()
conn.close()
print("migrate done")
