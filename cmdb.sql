-- cmdb.sql
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS assets (
  id           INTEGER PRIMARY KEY,
  hostname     TEXT NOT NULL UNIQUE,
  env          TEXT NOT NULL CHECK (env IN ('prod','dev','test','lab')),
  owner        TEXT NOT NULL,
  function     TEXT NOT NULL,
  criticality  INTEGER NOT NULL CHECK (criticality BETWEEN 1 AND 5),
  lifecycle    TEXT NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active','retired','quarantined')),
  updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_ips (
  id        INTEGER PRIMARY KEY,
  asset_id  INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  ip        TEXT NOT NULL UNIQUE,
  primary_ip INTEGER NOT NULL DEFAULT 0 CHECK (primary_ip IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_assets_env ON assets(env);
CREATE INDEX IF NOT EXISTS idx_asset_ips_asset ON asset_ips(asset_id);
