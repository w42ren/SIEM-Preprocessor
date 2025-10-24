# Fixing bug and re-running generation of synthetic auth.log
import csv, random, datetime, ipaddress, os
from pathlib import Path

random.seed(42)

ASSETS_CSV = "assets.csv"
OUT_PATH = "auth_synthetic.log"

# Read assets.csv (expected headers: hostname, ip, env, owner, function, criticality)
assets = []
with open(ASSETS_CSV, newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for r in reader:
        # ensure minimal fields
        hostname = r.get("hostname") or r.get("host") or r.get("Hostname") or ""
        ip = r.get("ip") or r.get("ip_address") or r.get("IP") or ""
        if hostname:
            assets.append({"hostname": hostname.strip(), "ip": ip.strip(), "row": r})

if not assets:
    raise SystemExit("No assets found in assets.csv - please check the file.")

# Helpers for log line formatting
def fmt_ts(dt):
    return dt.strftime("%b %e %H:%M:%S")  # matches syslog spacing (single-digit day padded with space)

def random_source_ip():
    pools = [
        ("203.0.113.", 50, 255),
        ("198.51.100.", 1, 255),
        ("192.0.2.", 1, 255),
        ("45.82.112.", 1, 254),
        ("185.199.108.", 1, 254),
        ("51.15.23.", 1, 254),
    ]
    prefix, a, b = random.choice(pools)
    return f"{prefix}{random.randint(a,b)}"

# Username pools
usernames = ["root","admin","ubuntu","deploy","alice","bob","oracle","test","guest","pi","svc_backup","monitor"]

# Event templates
def failed_password_line(ts, host, pid, user, src_ip, port):
    return f"{fmt_ts(ts)} {host} sshd[{pid}]: Failed password for {user} from {src_ip} port {port} ssh2"

def invalid_user_line(ts, host, pid, user, src_ip, port):
    return f"{fmt_ts(ts)} {host} sshd[{pid}]: Invalid user {user} from {src_ip} port {port}"

def accepted_pubkey_line(ts, host, pid, user, src_ip, port, keytype="RSA", fingerprint="SHA256:Z5Qb..."):
    return f"{fmt_ts(ts)} {host} sshd[{pid}]: Accepted publickey for {user} from {src_ip} port {port} ssh2: {keytype} {fingerprint} (comment)"

def accepted_password_line(ts, host, pid, user, src_ip, port):
    return f"{fmt_ts(ts)} {host} sshd[{pid}]: Accepted password for {user} from {src_ip} port {port} ssh2"

def session_opened(ts, host, pid, user):
    return f"{fmt_ts(ts)} {host} sshd[{pid}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)"

def session_closed(ts, host, user):
    return f"{fmt_ts(ts)} {host} sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}"

def sudo_cmd(ts, host, user, cmd, tty="pts/0"):
    return f"{fmt_ts(ts)} {host} sudo:     {user} : TTY={tty} ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"

def sudo_session_open(ts, host, user):
    return f"{fmt_ts(ts)} {host} sudo: pam_unix(sudo:session): session opened for user root by {user}(uid=0)"

def sudo_session_close(ts, host):
    return f"{fmt_ts(ts)} {host} sudo: pam_unix(sudo:session): session closed for user root"

def cron_job(ts, host, pid, cmd):
    return f"{fmt_ts(ts)} {host} CRON[{pid}]: ({cmd['user']}) CMD ({cmd['cmd']})"

# Build events across multiple days
start_date = datetime.date(2025, 10, 5)
days = 10  # Sep 4-6
lines = []

pid_counter = 14000

for day_offset in range(days):
    day = start_date + datetime.timedelta(days=day_offset)
    # per host, generate a set of sessions and attacks
    for asset in assets:
        host = asset["hostname"]
        # number of events per host varies with 'criticality' if present, else random
        crit = asset["row"].get("criticality")
        try:
            crit_val = int(crit) if crit not in (None, "", "null") else 2
        except Exception:
            crit_val = 2
        base_events = random.randint(8, 20) + max(0, (5 - crit_val)) * 2

        # normal ops: occasional successful logins
        if random.random() < 0.4:
            # a deploy-like publickey event
            ts = datetime.datetime.combine(day, datetime.time(hour=random.randint(0,23), minute=random.randint(0,59), second=random.randint(0,59)))
            pid_counter += 1
            src_ip = random.choice(["192.0.2.10","198.51.100.42","198.51.100.7","203.0.113.9"])
            user = random.choice(["deploy","alice","bob","svc_backup"])
            lines.append(accepted_pubkey_line(ts, host, pid_counter, user, src_ip, random.randint(40000,65000)))
            pid_counter += 1
            lines.append(session_opened(ts, host, pid_counter, user))
            # some sudo activity
            if user in ("alice","bob"):
                pid_counter += 1
                lines.append(sudo_cmd(ts + datetime.timedelta(seconds=20), host, user, "/usr/bin/apt-get update"))
                pid_counter += 1
                lines.append(sudo_session_open(ts + datetime.timedelta(seconds=20), host, user))
                pid_counter += 1
                lines.append(sudo_session_close(ts + datetime.timedelta(seconds=40), host))

            # session close later
            pid_counter += 1
            # FIX: use new pid value in session_closed format, so pass pid explicitly
            lines.append(f"{fmt_ts(ts + datetime.timedelta(minutes=random.randint(1,20)))} {host} sshd[{pid_counter}]: pam_unix(sshd:session): session closed for user {user}")

        # add cron jobs once per day for some hosts
        if random.random() < 0.3:
            pid_counter += 1
            cron_cmd = {"user":"root", "cmd":"/usr/local/bin/backup.sh"}
            lines.append(cron_job(datetime.datetime.combine(day, datetime.time(hour=12, minute=30, second=0)), host, pid_counter, cron_cmd))

        # simulate failed attempts / brute force from external IPs
        num_attack_bursts = random.choice([0,1,1,2])
        for _ in range(num_attack_bursts):
            attacker_ip = random_source_ip()
            port = random.randint(32000, 56000)
            burst_start = datetime.datetime.combine(day, datetime.time(hour=random.randint(0,23), minute=random.randint(0,59), second=random.randint(0,59)))
            if random.random() < 0.6:
                attempts = random.randint(3,12)
                for i in range(attempts):
                    pid_counter += 1
                    user = random.choice(["admin","root","ubuntu","test","oracle","guest","pi"])
                    lines.append(invalid_user_line(burst_start + datetime.timedelta(seconds=i*2), host, pid_counter, user, attacker_ip, port))
                    pid_counter += 1
                    lines.append(failed_password_line(burst_start + datetime.timedelta(seconds=i*2+1), host, pid_counter, user, attacker_ip, port))
                pid_counter += 1
                lines.append(f"{fmt_ts(burst_start + datetime.timedelta(seconds=attempts*2+1))} {host} sshd[{pid_counter}]: error: maximum authentication attempts exceeded for root from {attacker_ip} port {port} ssh2 [preauth]")
                pid_counter += 1
                lines.append(f"{fmt_ts(burst_start + datetime.timedelta(seconds=attempts*2+2))} {host} sshd[{pid_counter}]: Disconnecting authenticating user root {attacker_ip} port {port}: Too many authentication failures [preauth]")
            else:
                attempts = random.randint(1,4)
                for i in range(attempts):
                    pid_counter += 1
                    user = random.choice(["oracle","admin","root"])
                    lines.append(invalid_user_line(burst_start + datetime.timedelta(seconds=i*3), host, pid_counter, user, attacker_ip, port))
                    pid_counter += 1
                    lines.append(failed_password_line(burst_start + datetime.timedelta(seconds=i*3+1), host, pid_counter, user, attacker_ip, port))
                pid_counter += 1
                lines.append(f"{fmt_ts(burst_start + datetime.timedelta(seconds=attempts*3+1))} {host} sshd[{pid_counter}]: Connection closed by {attacker_ip} port {port} [preauth]")

        # add a few random noisy failed attempts spread through the day
        for _ in range(random.randint(0,3)):
            ts = datetime.datetime.combine(day, datetime.time(hour=random.randint(0,23), minute=random.randint(0,59), second=random.randint(0,59)))
            pid_counter += 1
            src = random_source_ip()
            user = random.choice(["admin","root","guest","pi"])
            lines.append(failed_password_line(ts, host, pid_counter, user, src, random.randint(30000,60000)))

# shuffle and write
# random.shuffle(lines)
p = Path(OUT_PATH)
with p.open("w", encoding="utf-8") as f:
    for ln in lines:
        f.write(ln + "\n")

print(f"Generated synthetic auth.log with {len(lines)} lines at: {OUT_PATH}")
