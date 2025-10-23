#!/usr/bin/env python3
"""
SSH auth.log preprocessor -> aggregated JSONL for SIEM.

- Parses "Failed password" lines from syslog-style /var/log/auth.log
- Aggregates counts per (host, src_ip, fixed time window)
- Joins asset metadata from a CSV (hostname, ip, env, owner, function, criticality)
- Applies dynamic thresholds based on asset.criticality
- Writes JSONL summary events

Usage:
  python ssh_auth_agg.py --input /var/log/auth.log \
                         --assets assets.csv \
                         --out ssh_failed_agg.jsonl \
                         --window 5

Inputs can be repeated and may include .gz files:
  python ssh_auth_agg.py --input auth.log auth.log.1.gz
"""

import argparse
import gzip
import io
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Dict, Iterable, Optional, Tuple

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
    Returns a dict:
      counts[(host, src_ip, window_start_dt)] = count
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

def write_jsonl(counts: Counter, assets: Dict[str, Dict], window_minutes: int, out_path: str):
    # group by key and write
    with (open(out_path, "w", encoding="utf-8") if out_path != "-" else
          io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")) as out:
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
            out.write(json.dumps(evt) + "\n")

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
    args = ap.parse_args()

    assets = load_assets_csv(args.assets)
    counts = aggregate(args.input, args.window, args.year)
    write_jsonl(counts, assets, args.window, args.out)

if __name__ == "__main__":
    main()
