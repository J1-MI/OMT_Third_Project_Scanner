-- scan_runs: 스캔 실행 감사 기록
CREATE TABLE IF NOT EXISTS scan_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_name TEXT,
  target TEXT,
  nmap_cmd TEXT,
  started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  finished_at TIMESTAMP,
  status TEXT,
  initiated_by TEXT,
  notes TEXT
);

-- hosts, ports (if not exist)
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id TEXT UNIQUE,
  address TEXT,
  hostname TEXT,
  state TEXT,
  last_seen TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id TEXT,
  port INTEGER,
  protocol TEXT,
  state TEXT,
  service TEXT,
  product TEXT,
  version TEXT
);

-- jobs for worker queue (simple sqlite queue)
CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT,
  profile TEXT,
  status TEXT DEFAULT 'queued',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- assets (domains/ip mapping & tags)
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject TEXT,
  subject_type TEXT,
  tag TEXT,
  meta TEXT,
  last_seen TIMESTAMP
);
