from __future__ import annotations

import os
import sys
from pathlib import Path

from mitmproxy import http

COMMON = Path(os.environ.get("COMMON", "/opt/traffic"))

sys.path.insert(0, str(COMMON))

import sni as sni_lists


class SniBlock:
    def __init__(self) -> None:
        self.blocked = sni_lists.load("domain", COMMON / "lists")["black"]

    def request(self, flow: http.HTTPFlow) -> None:
        name = getattr(flow.client_conn, "sni", None) or flow.request.pretty_host
        if sni_lists.blocks(self.blocked, name):
            flow.kill()


addons = [SniBlock()]
