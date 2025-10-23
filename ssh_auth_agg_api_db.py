#!/usr/bin/env python3
"""
SSH auth.log preprocessor -> aggregated JSONL for SIEM + optional POST to Node/LowDB API.

Features:
- Parses "Failed password" lines from syslog-style /var/log/auth.log
- Aggregates counts per (host, src_ip, fixed time window)
- Enriches events from an asset inventory stored in SQLite (preferred) or CSV (fallback)
- Applies dynamic thresholds based on asset.criticality
- Writes JSONL summary events (default stdout or file)
- Optionally POSTs events to a Node.js API (/v1/ssh-failures) with:
    - Bearer token authentication
    - Idempotency-Key header (SHA256 of canonical fields)
    - Per-event retries or batch POST mode
    - Dead-letter queue file for failed posts
"""

from __future__ import annotations
import argparse
import csv
import gzip
import io
import json
import os
import re
import sys
import time
import hashlib
import sqlite3
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, Iterable, Optional, Tuple, List

# optional dependency for HTTP posting
try:
    import requests
except Exception:
    requests = None

# Month name -> month number mapping for syslog timestamps
MONTHS = {m: i for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1)}

# Example line matched:
# Sep  4 01:12:08 web01 sshd[14321]: Failed password for root from 203.0.113.5 port 53211 ssh2
LINE_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password.*?\sfrom\s+(?P<ip>[0-9.]+)\b"
)

def open_maybe_gz(path: str) -> io.TextIOBase:
    if path == "-":
        return io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")

def parse_line(line: str, default_year: int) -> Optional[Tuple[str, str, datetime]]:
    m = LINE_RE.search(line)
    if not m:
        return None
    mon = MONTHS.get(m.group("mon"))
    if not mon:
        return None
    day = int(m.group("day"))
    hh, mm, ss = map(int, m.group("time").split(":"))
    # auth.log lacks year; assume current year (override via CLI if needed)
    ts = datetime(default_year, mon, day, hh, mm, ss)
    host = m.group("host")
    ip = m.group("ip")
    return host, ip, ts

def floor_to_window(ts: datetime, window_minutes: int) -> datetime:
    return ts.replace(minute=(ts.minute // window_minutes) * window_minutes,
                      second=0, microsecond=0)

# ---------------- asset loading ----------------

def load_assets_from_db(
    db_path: Optional[str],
    table_assets: str = "assets",
    table_ips: str = "asset_ips",
    lifecycle_filter: str = "active",
    csv_fallback: Optional[str] = None,
) -> Dict[str, Dict]:
    """
    Load assets from SQLite CMDB schema:
      - assets(id, hostname, env, owner, function, criticality, lifecycle, updated_at)
      - asset_ips(id, asset_id -> assets.id, ip, primary_ip)

    Picks primary IP (primary_ip=1) if present, else first IP by id.
    lifecycle_filter: 'active' (default) | 'retired' | 'quarantined' | 'any'
    Falls back to CSV if DB missing/unreadable.
    """
    assets: Dict[str, Dict] = {}

    def _normalise_mapping(row_map: Dict) -> Optional[Tuple[str, Dict]]:
        hostname = row_map.get("hostname")
        if not hostname:
            return None
        asset = {
            "hostname": hostname,
            "ip": row_map.get("ip"),
            "env": row_map.get("env"),
            "owner": row_map.get("owner"),
            "function": row_map.get("function"),
            "criticality": row_map.get("criticality"),
        }
        # normalise criticality -> int or None
        crit = asset.get("criticality")
        try:
            asset["criticality"] = int(crit) if crit is not None and crit != "" else None
        except Exception:
            asset["criticality"] = None
        return hostname, asset

    # Try DB
    if db_path:
        if not os.path.exists(db_path):
            sys.stderr.write(f"[WARN] assets DB not found at {db_path}; falling back to CSV if provided\n")
        else:
            try:
                # validate identifiers (table names)
                for tbl in (table_assets, table_ips):
                    if not isinstance(tbl, str) or not re.match(r"^[A-Za-z0-9_-]+$", tbl):
                        raise ValueError(f"Invalid table name: {tbl}")
                if lifecycle_filter not in ("active", "retired", "quarantined", "any"):
                    raise ValueError("Invalid lifecycle_filter (use: active|retired|quarantined|any)")

                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()

                # WHERE clause for lifecycle
                where_lifecycle = "" if lifecycle_filter == "any" else "WHERE a.lifecycle = ?"
                params = [] if lifecycle_filter == "any" else [lifecycle_filter]

                # Select primary IP if available; else first ip by id.
                # The correlated subquery orders by primary_ip DESC so 1 wins, then by id ASC.
                q = f"""
                SELECT
                  a.hostname,
                  a.env,
                  a.owner,
                  a.function,
                  a.criticality,
                  (
                    SELECT ip
                    FROM {table_ips} ai
                    WHERE ai.asset_id = a.id
                    ORDER BY ai.primary_ip DESC, ai.id ASC
                    LIMIT 1
                  ) AS ip
                FROM {table_assets} a
                {where_lifecycle}
                """
                cur.execute(q, params)
                rows = cur.fetchall()
                for r in rows:
                    row_map = dict(r)
                    nr = _normalise_mapping(row_map)
                    if nr:
                        hostname, asset = nr
                        assets[hostname] = asset

                conn.close()
                if assets:
                    return assets
                # fall through to CSV if no rows
            except Exception as e:
                sys.stderr.write(f"[WARN] SQLite read failed ({e}); falling back to CSV if provided\n")

    # Fallback CSV
    if csv_fallback:
        try:
            import csv
            with open(csv_fallback, "r", encoding="utf-8") as f:
                r = csv.DictReader(f)
                for row in r:
                    nr = _normalise_mapping(row)
                    if nr:
                        hostname, asset = nr
                        assets[hostname] = asset
        except Exception as e:
            sys.stderr.write(f"[WARN] Error reading CSV {csv_fallback}: {e}\n")

    return assets


# Backwards-compatible alias (if other parts call load_assets_csv)
def load_assets_csv(path: Optional[str]) -> Dict[str, Dict]:
    if not path:
        return {}
    try:
        return load_assets_from_db(None, csv_fallback=path)
    except Exception:
        return {}

# ---------------- thresholds & aggregation ----------------

def threshold_for(criticality: Optional[int]) -> int:
    if criticality is None:
        return 10
    if criticality >= 5:
        return 3
    if criticality >= 4:
        return 5
    if criticality >= 3:
        return 8
    return 10

def aggregate(inputs: Iterable[str], window_minutes: int, default_year: int) -> Counter:
    """
    Returns a Counter keyed by (host, src_ip, window_start_dt) -> count
    """
    counts: Counter = Counter()
    for path in inputs:
        with open_maybe_gz(path) as fh:
            for line in fh:
                parsed = parse_line(line, default_year)
                if not parsed:
                    continue
                host, ip, ts = parsed
                win_start = floor_to_window(ts, window_minutes)
                counts[(host, ip, win_start)] += 1
    return counts

# ---------------- idempotency + API helpers ----------------

def idem_key(evt: dict) -> str:
    """
    Create a stable idempotency key so replays don't duplicate.
    Tune fields if you change schema.
    """
    base = "|".join([
        evt.get("window_start", ""),
        evt.get("host", ""),
        evt.get("src_ip", ""),
        str(evt.get("fail_count", "")),
        str(evt.get("threshold", "")),
    ])
    return hashlib.sha256(base.encode()).hexdigest()

def post_one(record: dict, api_url: str, api_token: str, timeout: float, retries: int) -> bool:
    if requests is None:
        sys.stderr.write("[WARN] requests not installed; cannot POST to API\n")
        return False

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_token}",
        "Idempotency-Key": idem_key(record),
    }
    payload = json.dumps(record, ensure_ascii=False)
    backoff = 0.5
    for attempt in range(1, max(1, retries) + 1):
        try:
            r = requests.post(api_url, headers=headers, data=payload, timeout=timeout)
            if 200 <= r.status_code < 300:
                return True
            if r.status_code == 409:  # duplicate
                return True
            if 400 <= r.status_code < 500:
                sys.stderr.write(f"[API] Client error {r.status_code}: {r.text}\n")
                return False
        except Exception as e:
            sys.stderr.write(f"[API] Attempt {attempt} failed: {e}\n")
        time.sleep(backoff)
        backoff *= 2
    return False

def post_batch(records: List[dict], api_url: str, api_token: str, timeout: float, retries: int) -> bool:
    if requests is None:
        sys.stderr.write("[WARN] requests not installed; cannot POST to API\n")
        return False

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_token}",
    }
    backoff = 0.5
    for attempt in range(1, max(1, retries) + 1):
        try:
            r = requests.post(api_url, headers=headers, json=records, timeout=timeout)
            if 200 <= r.status_code < 300 or r.status_code == 409:
                return True
            if 400 <= r.status_code < 500:
                sys.stderr.write(f"[API] Client error {r.status_code}: {r.text}\n")
                return False
        except Exception as e:
            sys.stderr.write(f"[API] Batch attempt {attempt} failed: {e}\n")
        time.sleep(backoff)
        backoff *= 2
    return False

# ---------------- writing and posting pipeline ----------------

def write_jsonl_and_maybe_post(counts: Counter, assets: Dict[str, Dict], window_minutes: int,
                               out_path: str,
                               api_url: Optional[str],
                               api_token: Optional[str],
                               api_timeout: float,
                               api_retries: int,
                               batch_mode: bool):
    """
    Writes JSONL and (if api_url provided) posts to API.
    In batch mode, collects all and POSTs once at end as an array.
    """
    if out_path == "-":
        out_fh = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
        close_out = False
    else:
        out_fh = open(out_path, "w", encoding="utf-8")
        close_out = True

    dlq_path = "ssh_failed_agg.dlq.jsonl"
    batch: List[dict] = []

    try:
        for (host, ip, win_start), fail_count in sorted(counts.items(), key=lambda x: (x[0][2], -x[1])):
            win_end = win_start + timedelta(minutes=window_minutes)
            asset = assets.get(host, {})
            crit = asset.get("criticality")
            thr = threshold_for(crit)
            evt = {
                "event_type": "ssh_failed_agg",
                "timestamp": win_start.isoformat(),   # ensure timestamp present (for server)
                "host": host,
                "src_ip": ip,
                "fail_count": fail_count,
                "window_start": win_start.isoformat(),
                "window_end": win_end.isoformat(),
                "asset": {
                    "hostname": asset.get("hostname"),
                    "ip": asset.get("ip"),
                    "env": asset.get("env"),
                    "owner": asset.get("owner"),
                    "function": asset.get("function"),
                    "criticality": crit,
                },
                "threshold": thr,
                "alert": bool(fail_count >= thr),
                "enrichment_version": "v1"
            }

            # always write JSONL (as you do today)
            out_fh.write(json.dumps(evt, ensure_ascii=False) + "\n")

            # optionally send to API
            if api_url and api_token:
                if batch_mode:
                    # tag the idem key in-record for server-side dedup if desired
                    evt["_idem"] = idem_key(evt)
                    batch.append(evt)
                else:
                    ok = post_one(evt, api_url, api_token, api_timeout, api_retries)
                    if not ok:
                        with open(dlq_path, "a", encoding="utf-8") as dlq:
                            dlq.write(json.dumps(evt, ensure_ascii=False) + "\n")

        # if batching, send once
        if api_url and api_token and batch_mode and batch:
            ok = post_batch(batch, api_url, api_token, api_timeout, api_retries)
            if not ok:
                with open(dlq_path, "a", encoding="utf-8") as dlq:
                    for evt in batch:
                        dlq.write(json.dumps(evt, ensure_ascii=False) + "\n")
    finally:
        if close_out:
            out_fh.close()

# ---------------- CLI and main ----------------

def main():
    ap = argparse.ArgumentParser(description="Aggregate SSH failed logins and enrich with asset metadata.")
    ap.add_argument("--input", "-i", nargs="+", default=["auth.log"],
                    help="Input log files (use '-' for stdin; .gz supported).")
    ap.add_argument("--assets", "-a", default=None,
                    help="Asset inventory CSV with headers: hostname,ip,env,owner,function,criticality")
    ap.add_argument("--assets-db", default=os.getenv("SSH_ASSETS_DB","cmdb.sqlite"),
                    help="Path to SQLite CMDB DB file. Env: SSH_ASSETS_DB")
    ap.add_argument("--assets-table", default=os.getenv("SSH_ASSETS_TABLE", "assets"),
                    help="Assets table name (default: assets). Env: SSH_ASSETS_TABLE")
    ap.add_argument("--assets-ips-table", default=os.getenv("SSH_ASSETS_IPS_TABLE", "asset_ips"),
                    help="Asset IPs table name (default: asset_ips). Env: SSH_ASSETS_IPS_TABLE")
    ap.add_argument("--assets-lifecycle", default=os.getenv("SSH_ASSETS_LIFECYCLE", "active"),
                    choices=["active","retired","quarantined","any"],
                    help="Lifecycle filter for assets (default: active). Use 'any' to include all.")
    ap.add_argument("--out", "-o", default="-",
                    help="Output JSONL file (use '-' for stdout).")
    ap.add_argument("--window", "-w", type=int, default=5,
                    help="Aggregation window size in minutes (default: 5).")
    ap.add_argument("--year", type=int, default=datetime.now().year,
                    help="Year to assume for auth.log timestamps (default: current year).")

    # --- API options ---
    ap.add_argument("--api-url", default=os.getenv("SSH_API_URL"),
                    help="POST endpoint (e.g., http://localhost:8080/v1/ssh-failures). Env: SSH_API_URL")
    ap.add_argument("--api-token", default=os.getenv("SSH_API_TOKEN"),
                    help="Bearer token for API. Env: SSH_API_TOKEN")
    ap.add_argument("--api-timeout", type=float, default=float(os.getenv("SSH_API_TIMEOUT", "5")),
                    help="HTTP timeout seconds (default: 5). Env: SSH_API_TIMEOUT")
    ap.add_argument("--api-retries", type=int, default=int(os.getenv("SSH_API_RETRIES", "3")),
                    help="HTTP retries (default: 3). Env: SSH_API_RETRIES")
    ap.add_argument("--batch", action="store_true",
                    help="Send one array POST at the end instead of per-event POSTs.")

    args = ap.parse_args()

    # If API flags are supplied but requests isn't installed, warn & continue file-only.
    if (args.api_url or args.api_token) and requests is None:
        sys.stderr.write("[WARN] requests not available; API POST disabled. `pip install requests`\n")
        args.api_url = None
        args.api_token = None

    # Load assets (DB preferred, CSV fallback)
    assets = load_assets_from_db(
        args.assets_db,
        table_assets=args.assets_table,
        table_ips=args.assets_ips_table,
        lifecycle_filter=args.assets_lifecycle,
        csv_fallback=args.assets,   # optional legacy CSV
    )


    # Aggregate events
    counts = aggregate(args.input, args.window, args.year)

    # Write JSONL and optionally post
    write_jsonl_and_maybe_post(
        counts, assets, args.window, args.out,
        api_url=args.api_url,
        api_token=args.api_token,
        api_timeout=args.api_timeout,
        api_retries=args.api_retries,
        batch_mode=args.batch
    )

if __name__ == "__main__":
    main()
