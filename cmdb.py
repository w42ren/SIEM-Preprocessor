import sqlite3, csv, datetime, pathlib

DB = "cmdb.sqlite"

def connect():
    con = sqlite3.connect(DB)
    con.execute("PRAGMA foreign_keys=ON;")
    return con

def init_schema(con):
    con.executescript(pathlib.Path("cmdb.sql").read_text())

def upsert_asset(con, *, hostname, env, owner, function, criticality, lifecycle="active", ips=None):
    now = datetime.datetime.utcnow().isoformat(timespec="seconds")+"Z"
    con.execute("""
        INSERT INTO assets(hostname,env,owner,function,criticality,lifecycle,updated_at)
        VALUES(?,?,?,?,?,?,?)
        ON CONFLICT(hostname) DO UPDATE SET
            env=excluded.env, owner=excluded.owner, function=excluded.function,
            criticality=excluded.criticality, lifecycle=excluded.lifecycle, updated_at=excluded.updated_at
    """, (hostname, env, owner, function, criticality, lifecycle, now))
    asset_id = con.execute("SELECT id FROM assets WHERE hostname=?", (hostname,)).fetchone()[0]

    ips = ips or []
    for i, ip in enumerate(ips):
        # primary_ip = 1 for the first IP
        con.execute("""
            INSERT INTO asset_ips(asset_id, ip, primary_ip)
            VALUES(?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
                asset_id=excluded.asset_id, primary_ip=excluded.primary_ip
        """, (asset_id, ip, 1 if i == 0 else 0))

def export_csv(con, out_path="assets.csv"):
    rows = con.execute("""
        SELECT
          a.hostname,
          COALESCE(
            (SELECT ip FROM asset_ips ai WHERE ai.asset_id=a.id AND ai.primary_ip=1 LIMIT 1),
            (SELECT MIN(ip) FROM asset_ips ai WHERE ai.asset_id=a.id)
          ) AS ip,
          a.env, a.owner, a.function, a.criticality
        FROM assets a
        WHERE a.lifecycle='active'
        ORDER BY a.hostname
    """)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["hostname","ip","env","owner","function","criticality"])
        w.writerows(rows)

if __name__ == "__main__":
    con = connect()
    init_schema(con)
    # sample data
    # Example: assume `con` is your DB/connection object and upsert_asset(con, ...) is available.

    upsert_asset(con, hostname="web01",    env="prod",  owner="Web Team",    function="public_web",     criticality=4, ips=["10.0.1.10"])
    upsert_asset(con, hostname="db01",     env="prod",  owner="DBA",         function="customer_db",     criticality=5, ips=["10.0.1.20"])
    upsert_asset(con, hostname="app01",    env="prod",  owner="App Team",    function="order_processing", criticality=4, ips=["10.0.1.30"])
    upsert_asset(con, hostname="app02",    env="dev", owner="App Team",    function="order_processing", criticality=3, ips=["10.0.2.31"])
    upsert_asset(con, hostname="lb01",     env="prod",  owner="NetOps",      function="load_balancer",    criticality=5, ips=["10.0.1.5","10.0.1.6"])
    upsert_asset(con, hostname="bastion01",env="prod",  owner="SecOps",      function="bastion_host",     criticality=5, ips=["10.0.1.100"])
    upsert_asset(con, hostname="ci01",     env="dev",   owner="Build Team",  function="ci_cd_runner",     criticality=2, ips=["10.0.3.10"])
    upsert_asset(con, hostname="ns01",     env="prod",  owner="NetOps",      function="dns_authoritative", criticality=4, ips=["10.0.1.2"])
    upsert_asset(con, hostname="storage01",env="prod",  owner="Storage Team", function="object_store",     criticality=4, ips=["10.0.1.40","10.0.1.41"])
    upsert_asset(con, hostname="vpn01",    env="prod",  owner="NetOps",      function="vpn_gateway",      criticality=3, ips=["10.0.1.254"])

    con.commit()
    export_csv(con, "assets.csv")
    print("Wrote assets.csv")
