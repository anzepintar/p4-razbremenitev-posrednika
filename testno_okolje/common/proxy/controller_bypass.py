from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request

from mitmproxy import tls

CONTROLLER = os.environ.get("CONTROLLER_URL", "http://10.20.3.1:8080")
TIMEOUT = float(os.environ.get("DECIDE_TIMEOUT", "1.0"))


def _fetch(src: str) -> str:
    with urllib.request.urlopen(f"{CONTROLLER}/decide?src={src}", timeout=TIMEOUT) as response:
        return json.load(response)["action"]


class ControllerBypass:
    async def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        src = data.context.client.peername[0]

        try:
            action = await asyncio.get_running_loop().run_in_executor(None, _fetch, src)
        except (urllib.error.URLError, OSError, ValueError, KeyError):
            # Ob nedosegljivem krmilniku raje pregledamo, kot da bi promet spustili mimo.
            action = "inspect"

        # mitmproxy zna obiti le TCP; ob ignore_connection na QUIC se UDPLayer sesuje.
        if action == "direct" and data.context.client.transport_protocol == "tcp":
            data.ignore_connection = True


addons = [ControllerBypass()]
