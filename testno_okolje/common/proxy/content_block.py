from __future__ import annotations

import os
import re
from pathlib import Path

from mitmproxy import http

RULES = Path(os.environ.get("RULES", "/opt/traffic/proxy/rules.txt"))
THRESHOLD = int(os.environ.get("BLOCK_THRESHOLD", "100"))

BLOCK_PAGE = b"""<!doctype html>
<html lang="sl"><head><meta charset="utf-8"><title>Blokirano</title></head>
<body><h1>Stran je blokirana</h1>
<p>Posrednik je v vsebini strani prepoznal phishing.</p></body></html>
"""


def load_rules(path: Path) -> list[tuple[int, str, re.Pattern]]:
    rules = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        weight, name, pattern = line.split(maxsplit=2)
        rules.append((int(weight), name, re.compile(pattern, re.IGNORECASE)))
    return rules


class ContentBlock:
    def __init__(self) -> None:
        # Brez pravilnika nic ne blokiramo, da napaka ne pokvari meritve.
        self.rules = load_rules(RULES) if RULES.is_file() else []

    def response(self, flow: http.HTTPFlow) -> None:
        if not self.rules or flow.response is None:
            return
        if "text/html" not in flow.response.headers.get("content-type", "").lower():
            return

        body = flow.response.content or b""
        if not body:
            return

        text = body.decode("utf-8", "replace")
        matched = [(weight, name) for weight, name, rx in self.rules if rx.search(text)]
        if sum(weight for weight, _ in matched) < THRESHOLD:
            return

        flow.response = http.Response.make(
            403,
            BLOCK_PAGE,
            {
                "Content-Type": "text/html; charset=utf-8",
                # Enaki glavi kot Caddyjevi, da runner vrstico pripise pravi domeni.
                "X-Domain": flow.request.host_header or flow.request.pretty_host,
                "X-Sni": getattr(flow.client_conn, "sni", None) or "",
                "X-Block": ",".join(name for _, name in matched),
            },
        )


addons = [ContentBlock()]
