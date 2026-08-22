"""Najmanjsi odjemalec za Marionette, vgrajen daljinski protokol firefoxa.

Firefox nima ustreznice za chromiumov --dump-dom, ima pa Marionette (zastavica
--marionette). Protokol je dolzinsko predponirani JSON: ukaz je `<dolzina>:[0, id,
ime, parametri]`, odgovor pa `<dolzina>:[1, id, napaka, izid]`. Zato zanj ni
potrebna nobena zunanja knjiznica ne geckodriver.

Sele to nam da uporabljeni protokol iz prve roke:
performance.getEntriesByType("navigation")[0].nextHopProtocol.
"""
from __future__ import annotations

import asyncio
import json

READ_LIMIT = 16 * 1024 * 1024

NAVIGATION_SCRIPT = (
    "const e = performance.getEntriesByType('navigation')[0];"
    "return [document.title, document.documentURI, e ? e.nextHopProtocol : null];"
)


class MarionetteError(RuntimeError):
    """Seja ni uporabna vec; klicatelj naj firefox zazene znova."""


class Marionette:
    def __init__(self, port: int, host: str = "127.0.0.1") -> None:
        self.port = port
        self.host = host
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._next_id = 0

    async def connect(self, timeout: float = 90.0) -> dict:
        """Caka, da firefox odpre vrata, in prebere pozdrav."""
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            try:
                self._reader, self._writer = await asyncio.open_connection(
                    self.host, self.port, limit=READ_LIMIT
                )
                break
            except OSError:
                if asyncio.get_running_loop().time() >= deadline:
                    raise MarionetteError(
                        f"firefox ni odprl vrat {self.port} v {timeout:.0f}s"
                    )
                await asyncio.sleep(0.5)
        return await self._read(timeout=timeout)

    async def _read(self, timeout: float) -> dict | list:
        reader = self._reader
        if reader is None:
            raise MarionetteError("seja ni odprta")
        try:
            head = await asyncio.wait_for(reader.readuntil(b":"), timeout)
            length = int(head[:-1])
            body = await asyncio.wait_for(reader.readexactly(length), timeout)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                ConnectionError, ValueError) as error:
            raise MarionetteError(f"pokvarjen odgovor: {error}")
        except asyncio.TimeoutError:
            raise MarionetteError(f"odgovora ni bilo v {timeout:.0f}s")
        return json.loads(body)

    async def call(self, name: str, params: dict | None = None,
                   timeout: float = 60.0) -> tuple[dict | None, object]:
        """Vrne (napaka, izid). Napaka je slovar Marionette, ne izjema, ker je
        neuspesna navigacija pricakovan izid poskusa in ne okvara."""
        writer = self._writer
        if writer is None:
            raise MarionetteError("seja ni odprta")
        self._next_id += 1
        payload = json.dumps([0, self._next_id, name, params or {}]).encode()
        writer.write(str(len(payload)).encode() + b":" + payload)
        await writer.drain()

        message = await self._read(timeout)
        if not isinstance(message, list) or len(message) < 4:
            raise MarionetteError(f"nepricakovan odgovor: {message!r}")
        _, _, error, result = message[:4]
        value = result.get("value") if isinstance(result, dict) else result
        return error, value

    async def new_session(self, page_timeout_ms: int) -> None:
        error, _ = await self.call("WebDriver:NewSession", {})
        if error:
            raise MarionetteError(f"seje ni bilo mogoce odpreti: {error}")
        await self.call("WebDriver:SetTimeouts", {
            "pageLoad": page_timeout_ms, "script": page_timeout_ms,
        })

    async def visit(self, url: str, timeout: float) -> tuple[dict | None, list | None]:
        """Odpre naslov in prebere naslov strani, koncni URL in protokol."""
        error, _ = await self.call("WebDriver:Navigate", {"url": url}, timeout=timeout)
        if error:
            return error, None
        error, value = await self.call(
            "WebDriver:ExecuteScript", {"script": NAVIGATION_SCRIPT, "args": []},
            timeout=timeout,
        )
        if error:
            return error, None
        return None, value if isinstance(value, list) else None

    async def close(self) -> None:
        writer = self._writer
        self._reader, self._writer = None, None
        if writer is None:
            return
        try:
            writer.close()
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass
