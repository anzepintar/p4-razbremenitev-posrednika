from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from mitmproxy import tls

logger = logging.getLogger(__name__)

CONTROLLER = os.environ.get("CONTROLLER_URL", "http://10.20.3.1:8080")
DECIDE_LOG = Path(os.environ.get("DECIDE_LOG", "/opt/traffic/out/bypass.jsonl"))
TIMEOUT = float(os.environ.get("DECIDE_TIMEOUT", "1.0"))


def _fetch(src: str) -> str:
    url = f"{CONTROLLER}/decide?src={src}"
    with urllib.request.urlopen(url, timeout=TIMEOUT) as response:
        return json.load(response)["action"]


class ControllerBypass:
    def __init__(self) -> None:
        DECIDE_LOG.parent.mkdir(parents=True, exist_ok=True)
        logger.info("controller_bypass: krmilnik %s", CONTROLLER)

    async def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        src = data.context.client.peername[0]
        transport = data.context.client.transport_protocol
        started = time.perf_counter()

        try:
            action = await asyncio.get_running_loop().run_in_executor(None, _fetch, src)
            error = None
        except (urllib.error.URLError, OSError, ValueError, KeyError) as failure:
            # Ob nedosegljivem krmilniku raje pregledamo, kot da bi promet spustili mimo.
            action, error = "inspect", str(failure)

        # mitmproxy zna obiti le TCP; ob ignore_connection na QUIC se UDPLayer sesuje.
        forced = "quic" if action == "direct" and transport == "udp" else None
        if forced:
            action = "inspect"

        decide_ms = (time.perf_counter() - started) * 1000
        if action == "direct":
            data.ignore_connection = True

        self._log(
            {
                "ts": round(time.time(), 6),
                "src": src,
                "sni": data.client_hello.sni,
                "transport": transport,
                "action": action,
                "forced": forced,
                "decide_ms": round(decide_ms, 4),
                "error": error,
            }
        )

    def _log(self, row: dict) -> None:
        with DECIDE_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


addons = [ControllerBypass()]
