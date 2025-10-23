#!/usr/bin/env python3
"""
read_cmdb.py
-----------------
Read and print asset inventory from an SQLite CMDB.

Schema expected:
  - assets(id, hostname, env, owner, function, criticality, lifecycle, updated_at)
  - asset_ips(id, asset_id, ip, primary_ip)

Usage:
  python read_cmdb.py --db cmdb.sqlite
  python read_cmdb.py --db cmdb.sqlite --lifecycle active
  python read_cmdb.py --db cmdb.sqlite --json
"""

import argparse
import sqlite3
import json
import sys
from textwrap import shorten

def main():
    ap = argparse.ArgumentParser(description="Print assets and IPs from CMDB (SQLite).")
    ap.add_argument("--db", required=True, help="Path to cmdb SQLite database (e.g., cmdb.sqlite)")
    ap.add_argument("--table-assets", default="assets", help="Assets table name (default: assets)")
    ap.add_argument("--table-ips", default="asset_ips", help="Asset IPs table name (default: asset_ips)")
    ap.add_argument("--lifecycle", default="any", choices=["any","active","retired","quarantined"],
                    help="Filter by lifecycle (default: any)")
    ap.add_argument("--json", action="store_true", help="Output as JSON instead of text table")
    args = ap.parse_args()

    try:
        conn = sqlite3.connect(args.db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        where = "" if args.lifecycle == "any" else "WHERE a.lifecycle = ?"
        params = [] if args.lifecycle == "any" else [args.lifecycle]

        # Use underscores for argparse attributes:
        assets_tbl = args.table_assets
        ips_tbl = args.table_ips

        # correlated subquery picks primary IP if any, else first IP
        query = f"""
        SELECT
            a.id,
            a.hostname,
            (
              SELECT ip FROM {ips_tbl} ai
              WHERE ai.asset_id = a.id
              ORDER BY ai.primary_ip DESC, ai.id ASC
              LIMIT 1
            ) AS ip,
            a.env,
            a.owner,
            a.function,
            a.criticality,
            a.lifecycle,
            a.updated_at
        FROM {assets_tbl} a
        {where}
        ORDER BY a.env, a.hostname;
        """
        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()
    except sqlite3.Error as e:
        sys.stderr.write(f"[ERROR] SQLite: {e}\n")
        sys.exit(1)

    if args.json:
        json.dump([dict(r) for r in rows], sys.stdout, indent=2)
        sys.stdout.write("\n")
        return

    # pretty print
    print(f"{'ID':>3}  {'HOSTNAME':<20} {'IP':<15} {'ENV':<6} {'OWNER':<12} "
          f"{'FUNCTION':<12} {'CRIT':>4} {'LIFE':<12} {'UPDATED'}")
    print("-"*95)
    for r in rows:
        print(f"{r['id']:>3}  {shorten(r['hostname'],20):<20} {str(r['ip'] or '-'):15} "
              f"{r['env']:<6} {shorten(r['owner'],12):<12} {shorten(r['function'],12):<12} "
              f"{r['criticality']:>4} {r['lifecycle']:<12} {r['updated_at']}")
    print(f"\nTotal: {len(rows)} asset(s)")

if __name__ == "__main__":
    main()
