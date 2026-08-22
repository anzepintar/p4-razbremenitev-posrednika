from __future__ import annotations

import json
import os
import time
from pathlib import Path

from mitmproxy import http, tcp, udp

FLOW_LOG = Path(os.environ.get("FLOW_LOG", "/opt/traffic/out/proxy_flows.jsonl"))


class ProxyStats:
    def __init__(self) -> None:
        FLOW_LOG.parent.mkdir(parents=True, exist_ok=True)
        self._handle = None

    def done(self) -> None:
        if self._handle is not None:
            self._handle.close()

    def _open(self):
        if self._handle is not None:
            try:
                if os.fstat(self._handle.fileno()).st_ino == FLOW_LOG.stat().st_ino:
                    return self._handle
            except OSError:
                pass
            self._handle.close()
        self._handle = FLOW_LOG.open("a", encoding="utf-8")
        return self._handle

    def _write(self, kind: str, flow, host: str | None, version: str | None = None) -> None:
        address = getattr(flow.server_conn, "address", None)
        row = {
            "ts": round(time.time(), 6),
            "kind": kind,
            "host": (host or getattr(flow.client_conn, "sni", None)
                     or (address[0] if address else None)),
            # Razlicica protokola je neodvisna potrditev, katero pot je odjemalec
            # res ubral; pregled spleta jo primerja s tem, kar je zahteval.
            "http_version": version,
        }
        handle = self._open()
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        handle.flush()

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        self._write("http", flow, flow.request.host_header or flow.request.pretty_host,
                    flow.request.http_version)

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        self._write("tcp", flow, None)

    def udp_start(self, flow: udp.UDPFlow) -> None:
        self._write("udp", flow, None)


addons = [ProxyStats()]
