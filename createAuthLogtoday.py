#!/usr/bin/env python3
import datetime
import random
import ipaddress

# --- config ---
days = 10                  # number of days before now (1..days)
events_per_day = 15      # events per day (you can increase)
out_path = "auth_multi_before_now.log"

hosts = ["web01", "db01", "app01", "web02", "db02", "app02", "cache01", "proxy01", "lb01", "monitor01"]
# sample message templates (use {ip} where appropriate)
templates = [
    "sshd[14321]: Failed password for invalid user admin from {ip} port 53211 ssh2",
    "sshd[14502]: Accepted publickey for deploy from {ip} port 42102 ssh2: RSA SHA256:Z5Qb... (comment)",
    "sshd[15177]: Failed password for invalid user oracle from {ip} port 54491 ssh2",
    "sshd[17602]: Accepted password for alice from {ip} port 54022 ssh2",
    "sshd[18944]: Accepted publickey for bob from {ip} port 49822 ssh2: ED25519 SHA256:Pk2c..."
]

def random_public_ipv4():
    # pick from RFC1918-excluded ranges to look "public-ish"
    blocks = [
        ("203.0.113.0","203.0.113.255"),
        ("198.51.100.0","198.51.100.255"),
        ("192.0.2.0","192.0.2.255"),
        ("203.0.114.0","203.0.114.255"),
    ]
    start, end = random.choice(blocks)
    start_i = int(ipaddress.IPv4Address(start))
    end_i   = int(ipaddress.IPv4Address(end))
    return str(ipaddress.IPv4Address(random.randint(start_i, end_i)))

def fmt_syslog_ts(dt: datetime.datetime) -> str:
    # Format syslog timestamp like: "Sep  4 01:12:08" (month abbreviated, day padded with space)
    mon = dt.strftime("%b")
    day = f"{dt.day:2d}"   # leading space for single-digit days
    return f"{mon} {day} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"

def generate_before_now(days: int, events_per_day: int):
    now = datetime.datetime.now()
    lines = []
    for d in range(1, days + 1):
        base = now - datetime.timedelta(days=d)
        for _ in range(events_per_day):
            # jitter minutes/seconds so events don't all share the exact same time
            jitter_minutes = random.randint(-30, 30)
            jitter_seconds = random.randint(-30, 30)
            ts = base + datetime.timedelta(minutes=jitter_minutes, seconds=jitter_seconds)
            ts = ts.replace(microsecond=0)
            ts_str = fmt_syslog_ts(ts)

            host = random.choice(hosts)
            template = random.choice(templates)
            ip = random_public_ipv4()
            message = template.format(ip=ip)

            line = f"{ts_str} {host} {message}"
            lines.append(line)
    return lines

if __name__ == "__main__":
    lines = generate_before_now(days=days, events_per_day=events_per_day)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} lines spanning {days} days to {out_path}")
