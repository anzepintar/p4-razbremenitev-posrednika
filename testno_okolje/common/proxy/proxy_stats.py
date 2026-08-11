from __future__ import annotations

import json
import os
import time
from pathlib import Path

from mitmproxy import http

FLOW_LOG = Path(os.environ.get("FLOW_LOG", "/opt/traffic/out/proxy_flows.jsonl"))


class ProxyStats:
    # Steje zahteve, ki jih posrednik dejansko pregleda; obidene sem ne pridejo.
    def __init__(self) -> None:
        FLOW_LOG.parent.mkdir(parents=True, exist_ok=True)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        body = flow.response.content or b""
        row = {
            "ts": round(time.time(), 6),
            "src": flow.client_conn.peername[0] if flow.client_conn.peername else None,
            "host": flow.request.host_header or flow.request.pretty_host,
            "path": flow.request.path,
            "status": flow.response.status_code,
            "size": len(body),
            "content_type": flow.response.headers.get("content-type", ""),
            "http_version": flow.response.http_version,
        }
        with FLOW_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


addons = [ProxyStats()]
