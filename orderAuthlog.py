# Read the existing synthetic auth.log, sort lines by their syslog timestamp (month day time),
# and write a new chronologically ordered file.
from pathlib import Path
import datetime, calendar, re

IN_PATH = Path("auth_synthetic.log")
OUT_PATH = Path("auth_synthetic_sorted.log")
YEAR = 2025  # assume year for ordering

if not IN_PATH.exists():
    raise SystemExit(f"Input file not found: {IN_PATH}")

month_map = {m: i for i, m in enumerate(calendar.month_abbr) if m}
# Helper to parse syslog timestamp at line start: "Sep  4 01:12:08"
def parse_syslog_ts(line):
    # safe-guard: require at least 15 chars for timestamp "Mon dd HH:MM:SS"
    prefix = line[:15]
    # regex to extract month, day, time
    m = re.match(r'^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})', prefix)
    if not m:
        return None
    mon = m.group("mon")
    day = int(m.group("day"))
    hh, mm, ss = map(int, m.group("time").split(":"))
    month_num = month_map.get(mon)
    if not month_num:
        return None
    try:
        return datetime.datetime(YEAR, month_num, day, hh, mm, ss)
    except ValueError:
        return None

# Read lines and attach parsed datetime; keep original order index for stability
lines = IN_PATH.read_text(encoding="utf-8").splitlines()
entries = []
for idx, ln in enumerate(lines):
    ts = parse_syslog_ts(ln)
    if ts is None:
        # Put unparsable lines at the end with max timestamp plus index
        ts = datetime.datetime.max - datetime.timedelta(seconds=(len(lines)-idx))
    entries.append((ts, idx, ln))

# Sort by timestamp then original index
entries.sort(key=lambda x: (x[0], x[1]))

# Write sorted lines
with OUT_PATH.open("w", encoding="utf-8") as f:
    for ts, idx, ln in entries:
        f.write(ln + "\n")

print(f"Wrote sorted auth.log to: {OUT_PATH} ({len(entries)} lines)")
