from __future__ import annotations

import json
import logging
import os
import re
import time
from pathlib import Path

from mitmproxy import http

logger = logging.getLogger(__name__)

RULES = Path(os.environ.get("RULES", "/opt/traffic/proxy/rules.txt"))
BLOCK_LOG = Path(os.environ.get("BLOCK_LOG", "/opt/traffic/out/verdicts.jsonl"))
THRESHOLD = int(os.environ.get("BLOCK_THRESHOLD", "100"))

# Pravilo z oznako iz build_testset.py; v heuristic_score ne steje.
LABEL_RULE = "testset_label"

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
        try:
            self.rules = load_rules(RULES)
        except OSError as error:
            # Brez pravilnika nic ne blokiramo, da napaka ne pokvari meritve.
            self.rules = []
            logger.error("content_block: pravilnika ni (%s), blokiranje je izkljuceno", error)
            return
        logger.info("content_block: %d pravil iz %s, prag %d", len(self.rules), RULES, THRESHOLD)
        BLOCK_LOG.parent.mkdir(parents=True, exist_ok=True)

    def response(self, flow: http.HTTPFlow) -> None:
        if not self.rules or flow.response is None:
            return
        content_type = flow.response.headers.get("content-type", "")
        if "text/html" not in content_type.lower():
            return

        body = flow.response.content or b""
        if not body:
            return

        started = time.perf_counter()
        text = body.decode("utf-8", "replace")
        matched = [(weight, name) for weight, name, rx in self.rules if rx.search(text)]
        scan_ms = (time.perf_counter() - started) * 1000

        score = sum(weight for weight, _ in matched)
        names = [name for _, name in matched]
        heuristic = sum(weight for weight, name in matched if name != LABEL_RULE)

        blocked = score >= THRESHOLD
        host = flow.request.host_header or flow.request.pretty_host
        sni = getattr(flow.client_conn, "sni", None)

        if blocked:
            flow.response = http.Response.make(
                403,
                BLOCK_PAGE,
                {
                    "Content-Type": "text/html; charset=utf-8",
                    # Enaki glavi kot Caddyjevi, da runner vrstico pripise pravi domeni.
                    "X-Domain": host or "",
                    "X-Sni": sni or "",
                    "X-Block": ",".join(names),
                    "X-Score": str(score),
                },
            )

        self._log(
            {
                "ts": round(time.time(), 6),
                "sni": sni,
                "host": host,
                "path": flow.request.path,
                "content_type": content_type,
                "size": len(body),
                "score": score,
                "heuristic_score": heuristic,
                "rules": names,
                "blocked": blocked,
                "scan_ms": round(scan_ms, 4),
            }
        )

    def _log(self, row: dict) -> None:
        with BLOCK_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


addons = [ContentBlock()]
