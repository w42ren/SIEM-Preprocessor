# log_idem.py
from mitmproxy import http, ctx
import datetime
import os

LOGFILE = os.path.join(os.getcwd(), "idem_headers.log")

def request(flow: http.HTTPFlow) -> None:
    if "/v1/ssh-failures" in flow.request.path:
        idem = flow.request.headers.get("Idempotency-Key")
        line = f"{datetime.datetime.utcnow().isoformat()} {flow.request.method} {flow.request.pretty_url} Idempotency-Key: {idem}"
        ctx.log.info(line)
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
