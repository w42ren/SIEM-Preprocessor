#!/usr/bin/env python3
"""
SSH auth.log preprocessor -> aggregated JSONL for SIEM + optional POST to Node/LowDB API.

- Parses "Failed password" lines from syslog-style /var/log/auth.log
- Aggregates counts per (host, src_ip, fixed time window)
- Joins asset metadata from a CSV (hostname, ip, env, owner, function, criticality)
- Applies dynamic thresholds based on asset.criticality
- Writes JSONL summary events
- (Optional) POSTs events to a Node.js API (e.g., /v1/ssh-failures) with retries & idempotency

Usage:
  python ssh_auth_agg.py --input /var/log/auth.log \
                         --assets assets.csv \
                         --out ssh_failed_agg.jsonl \
                         --window 5 \
                         --api-url http://localhost:8080/v1/ssh-failures \
                         --api-token mysecrettoken123
"""

import argparse
import gzip
import io

import json
import os
import re
import sys
import time
import hashlib
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, Iterable, Optional, Tuple, List

try:
    import requests  # for API posting
except ImportError:
    requests = None  # handled below if API flags are used without requests installed

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

def load_assets_csv(path: Optional[str]) -> Dict[str, Dict]:
    """
    Returns: mapping hostname -> asset dict
    CSV headers expected: hostname, ip, env, owner, function, criticality
    """
    assets: Dict[str, Dict] = {}
    if not path:
        return assets
    import csv
    with open(path, "r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            hostname = row.get("hostname")
            if not hostname:
                continue
            # normalize: criticality to int if possible
            crit = row.get("criticality")
            try:
                crit_val = int(crit) if crit not in (None, "", "null") else None
            except ValueError:
                crit_val = None
            row["criticality"] = crit_val
            assets[hostname] = row
    return assets

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

def aggregate(inputs: Iterable[str], window_minutes: int, default_year: int):
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

# ------------------- API posting helpers -------------------

def idem_key(evt: dict) -> str:
    """
    Create a stable idempotency key so replays don't duplicate.
    Tune fields if you change schema.
    """
    # Use window (start), host, src_ip, fail_count, threshold
    base = "|".join([
        evt.get("window_start", ""),
        evt.get("host", ""),
        evt.get("src_ip", ""),
        str(evt.get("fail_count", "")),
        str(evt.get("threshold", "")),
    ])
    return hashlib.sha256(base.encode()).hexdigest()

def post_one(record: dict, api_url: str, api_token: str, timeout: float, retries: int) -> bool:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_token}",
        "Idempotency-Key": idem_key(record),
    }
    payload = json.dumps(record, ensure_ascii=False)
    backoff = 0.5
    for attempt in range(1, retries + 1):
        try:
            r = requests.post(api_url, headers=headers, data=payload, timeout=timeout)
            if 200 <= r.status_code < 300:
                return True
            if r.status_code == 409:  # treated as duplicate/success
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
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_token}",
    }
    backoff = 0.5
    for attempt in range(1, retries + 1):
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

# ------------------- writer -------------------

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

def main():
    ap = argparse.ArgumentParser(description="Aggregate SSH failed logins and enrich with asset metadata.")
    ap.add_argument("--input", "-i", nargs="+", default=["auth.log"],
                    help="Input log files (use '-' for stdin; .gz supported).")
    ap.add_argument("--assets", "-a", default=None,
                    help="Asset inventory CSV with headers: hostname,ip,env,owner,function,criticality")
    ap.add_argument("--out", "-o", default="-",
                    help="Output JSONL file (use '-' for stdout).")
    ap.add_argument("--window", "-w", type=int, default=5,
                    help="Aggregation window size in minutes (default: 5).")
    ap.add_argument("--year", type=int, default=datetime.now().year,
                    help="Year to assume for auth.log timestamps (default: current year).")

    # --- API options ---
    ap.add_argument("--api-url", default=os.getenv("SSH_API_URL"),
                    help="POST endpoint (e.g., http://localhost:8080/v1/ssh-failures). "
                         "Env: SSH_API_URL")
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

    assets = load_assets_csv(args.assets)
    counts = aggregate(args.input, args.window, args.year)

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
