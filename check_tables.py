import sqlite3

conn = sqlite3.connect("assets.db")
cur = conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cur.fetchall()
print("테이블 목록:", tables)
conn.close()
