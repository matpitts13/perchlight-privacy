-- perchlight-privacy v0.1. Times: *_at columns are "YYYY-MM-DD HH:MM:SS" UTC
-- (for the desktop app), *_ms columns are Unix milliseconds (for logic).
-- No page HTML is ever stored: findings keep at most 200 characters of
-- evidence, with email addresses masked.

CREATE TABLE sites (
  id TEXT PRIMARY KEY,
  host TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'api',          -- config | api
  own_hosts TEXT NOT NULL DEFAULT '[]',        -- JSON
  pages TEXT NOT NULL DEFAULT '["/"]',         -- JSON
  settings TEXT NOT NULL DEFAULT '{}',         -- JSON: discover, imprint, necessaryCookies, alertLevel, userAgent
  verify_token TEXT NOT NULL,
  verify_method TEXT,                          -- txt | file
  verified_scope TEXT,                         -- domain | host
  verified_name TEXT,                          -- the domain (TXT) or host (file) the proof covers
  verified_at TEXT,
  verify_failures INTEGER NOT NULL DEFAULT 0,
  verify_failed_ms INTEGER,                    -- first failure of the current run of failures
  state TEXT NOT NULL DEFAULT 'unverified',    -- unverified | active | verification_lost
  paused INTEGER NOT NULL DEFAULT 0,           -- editable in the app
  every TEXT NOT NULL DEFAULT '1d',            -- editable in the app; at least 6h
  next_scan_ms INTEGER,
  next_scan_at TEXT,
  last_scan_id TEXT,                           -- latest done or partial scan
  last_scan_at TEXT,
  last_status TEXT,
  high INTEGER NOT NULL DEFAULT 0,
  medium INTEGER NOT NULL DEFAULT 0,
  share_token_hash TEXT,                       -- SHA-256 of the share token; never the token
  config_error TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE scans (
  id TEXT PRIMARY KEY,                         -- time-sortable
  site_id TEXT NOT NULL,
  trigger TEXT NOT NULL,                       -- schedule | manual
  started_at TEXT NOT NULL,
  started_ms INTEGER NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL DEFAULT 'running',      -- running | done | partial | failed
  pages_ok INTEGER NOT NULL DEFAULT 0,
  pages_failed INTEGER NOT NULL DEFAULT 0,
  subrequests INTEGER NOT NULL DEFAULT 0,
  high INTEGER NOT NULL DEFAULT 0,
  medium INTEGER NOT NULL DEFAULT 0,
  low INTEGER NOT NULL DEFAULT 0,
  info INTEGER NOT NULL DEFAULT 0,
  new_count INTEGER NOT NULL DEFAULT 0,
  resolved_count INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  notes TEXT,                                  -- JSON: pages (status, error, truncated), consent managers, little HTML
  changes TEXT                                 -- JSON: { new: [...], resolved: [...] } (keys, checks, subjects, pages)
);
CREATE INDEX scans_site ON scans (site_id, id);

CREATE TABLE findings (
  scan_id TEXT NOT NULL,
  site_id TEXT NOT NULL,
  key TEXT NOT NULL,
  check_id TEXT NOT NULL,
  severity TEXT NOT NULL,                      -- high | medium | low | info
  page TEXT NOT NULL,
  subject TEXT NOT NULL,
  evidence TEXT NOT NULL,                      -- at most 200 characters, emails masked
  source TEXT NOT NULL DEFAULT 'static',
  first_seen_at TEXT NOT NULL,
  carried INTEGER NOT NULL DEFAULT 0,          -- 1: the page failed this scan; carried from the previous one
  PRIMARY KEY (scan_id, key)
);

CREATE TABLE mutes (
  site_id TEXT NOT NULL,
  key TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  at TEXT NOT NULL,
  PRIMARY KEY (site_id, key)
);

CREATE TABLE deliveries (
  id TEXT PRIMARY KEY,
  subject TEXT NOT NULL,
  kind TEXT NOT NULL,                          -- changes | verification_lost | scan_failing | recovered | test
  channel TEXT NOT NULL,
  status TEXT NOT NULL,                        -- pending | sending | retry | sent | failed | unknown | retry_requested
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at TEXT NOT NULL,
  sent_at TEXT
);
CREATE INDEX deliveries_created ON deliveries (created_at);

-- Counted Worker requests (admin, report, tick), per UTC day.
CREATE TABLE footprint (
  day TEXT NOT NULL,
  k TEXT NOT NULL,
  n INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, k)
);

CREATE TABLE state (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);

-- The desktop app's Findings screen: the latest completed scan of each site, most severe first.
CREATE VIEW latest_findings AS
  SELECT f.site_id, s.host, f.check_id, f.severity,
         CASE f.severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END AS severity_rank,
         f.page, f.subject, f.evidence, f.first_seen_at, f.key, f.carried,
         CASE WHEN m.key IS NULL THEN 0 ELSE 1 END AS muted, f.scan_id
  FROM findings f
  JOIN sites s ON s.id = f.site_id AND s.last_scan_id = f.scan_id
  LEFT JOIN mutes m ON m.site_id = f.site_id AND m.key = f.key;
