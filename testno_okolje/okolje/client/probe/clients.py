"""Izvedbe pregleda za curl, chromium in firefox.

Vsi trije obiscejo isti cilj, torej https://<koncni-gostitelj>/, in vrnejo vrstico
z istimi kljuci. Razlikujejo se po tem, kako povedo uporabljeni protokol:

- curl ga pove v http_version,
- chromium ga jamci le prek zastavice (--disable-quic ali --origin-to-force-quic-on),
- firefox ga pove v nextHopProtocol prek Marionette.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import verdicts
from .marionette import Marionette, MarionetteError

BROWSER = Path("/opt/traffic/browser")
CHROMIUM = BROWSER / "chromium.sh"
FIREFOX = BROWSER / "firefox.sh"

MARIONETTE_BASE_PORT = 2828
PROCESS_GRACE_S = 15.0


@dataclass(frozen=True)
class Target:
    rank: int
    domain: str
    host: str
    url: str
    categories: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Target":
        return cls(rank=int(data.get("rank") or 0), domain=data["domain"],
                   host=data.get("host") or data["domain"],
                   url=data.get("url") or f"https://{data['domain']}/",
                   categories=data.get("categories") or "")


@dataclass(frozen=True)
class Config:
    connect_timeout_s: float = 5.0
    max_time_s: float = 20.0
    page_timeout_s: float = 30.0
    cacert: str | None = None
    no_kyber: bool = False

    @property
    def budget_ms(self) -> int:
        return int(self.page_timeout_s * 1000)


def row(target: Target, client: str, proto: str, verdict: dict,
        *, ts: float, elapsed_ms: float) -> dict:
    return {
        "ts": round(ts, 6),
        "client": client,
        "proto": proto,
        "rank": target.rank,
        "domain": target.domain,
        "host": target.host,
        "url": target.url,
        "categories": target.categories,
        "elapsed_ms": round(elapsed_ms, 1),
        **verdict,
    }


async def run(argv: list[str], timeout: float, env: dict | None = None) -> tuple[int, str, str]:
    """Zazene proces in ga ob izteku ubije, da posamezna domena ne ustavi pregleda."""
    process = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env={**os.environ, **(env or {})},
    )
    try:
        out, err = await asyncio.wait_for(process.communicate(), timeout)
    except asyncio.TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(process.wait(), 10)
        return -1, "", f"iztek po {timeout:.0f}s"
    return process.returncode or 0, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


# --- curl ---------------------------------------------------------------------

async def probe_curl(target: Target, proto: str, cfg: Config) -> dict:
    argv = verdicts.curl_argv(
        target.url, proto,
        connect_timeout=cfg.connect_timeout_s, max_time=cfg.max_time_s,
        cacert=cfg.cacert,
    )
    code, out, err = await run(argv, cfg.max_time_s + PROCESS_GRACE_S)
    try:
        record = json.loads(out)
    except json.JSONDecodeError:
        return {"ok": False, "protocol": None, "http_code": None, "url_effective": None,
                "ms": None, "error": "curl:brez izpisa",
                "message": (err.strip() or f"koda {code}")[:200],
                "subject": None, "issuer": None}
    return verdicts.curl_verdict(record, proto)


async def follow(target: Target, cfg: Config) -> dict:
    """Korak 0: kam apex domena res pripelje. Uporabi HTTP/2, ker je najbolj
    razsirjen; iz url_effective nato nastane cilj za vse odjemalce."""
    argv = verdicts.curl_argv(
        target.url, "h2",
        connect_timeout=cfg.connect_timeout_s, max_time=cfg.max_time_s,
        cacert=cfg.cacert, follow=True,
    )
    code, out, _ = await run(argv, cfg.max_time_s + PROCESS_GRACE_S)
    try:
        record = json.loads(out)
    except json.JSONDecodeError:
        return {"ok": False, "url_effective": None, "error": f"curl:{code}"}
    exitcode = record.get("exitcode")
    return {
        "ok": not exitcode,
        "url_effective": record.get("url_effective"),
        "http_code": record.get("http_code") or None,
        "error": f"curl:{exitcode}" if exitcode else None,
        "message": record.get("errormsg") or None,
    }


# --- chromium -----------------------------------------------------------------

async def probe_chromium(target: Target, proto: str, cfg: Config) -> dict:
    profile = tempfile.mkdtemp(prefix="chromium-")
    env = {**verdicts.chromium_env(target.host, proto), "USER_DATA_DIR": profile}
    argv = [str(CHROMIUM), *verdicts.chromium_argv(target.url, budget_ms=cfg.budget_ms)]
    try:
        code, dom, err = await run(argv, cfg.page_timeout_s + PROCESS_GRACE_S, env=env)
    finally:
        shutil.rmtree(profile, ignore_errors=True)

    verdict = verdicts.chromium_verdict(dom, proto=proto, returncode=code)
    if not verdict["ok"] and not verdict.get("message"):
        verdict["message"] = tail(err)
    return verdict


def tail(text: str, lines: int = 3) -> str | None:
    """Zadnje vrstice stderr brez suma, ki ga chromium v vsebniku vedno izpise."""
    noise = ("dbus", "Fontconfig", "GPU", "vulkan", "gcm", "Registration")
    useful = [line for line in text.splitlines()
              if line.strip() and not any(word in line for word in noise)]
    return " | ".join(useful[-lines:])[:200] or None


# --- firefox ------------------------------------------------------------------

class FirefoxWorker:
    """Ena instanca firefoxa s svojim profilom in svojimi vrati Marionette.

    Firefox se za razliko od chromiuma ne zaganja na domeno, ampak enkrat na blok;
    posamezna domena je le WebDriver:Navigate. Ob okvari seje se zazene znova, da
    ena pokvarjena stran ne odnese preostanka bloka.
    """

    def __init__(self, index: int, proto: str, hosts: list[str], cfg: Config) -> None:
        self.index = index
        self.proto = proto
        self.hosts = hosts
        self.cfg = cfg
        self.port = MARIONETTE_BASE_PORT + index
        self.profile = Path(tempfile.mkdtemp(prefix=f"firefox-{index}-"))
        self._process: asyncio.subprocess.Process | None = None
        self._session: Marionette | None = None

    async def start(self) -> None:
        env = {
            **verdicts.firefox_env(self.hosts, self.proto, marionette_port=self.port,
                                   no_kyber=self.cfg.no_kyber),
            "PROFILE_DIR": str(self.profile),
        }
        self._process = await asyncio.create_subprocess_exec(
            str(FIREFOX), "--headless", "--marionette", "about:blank",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            env={**os.environ, **env},
        )
        session = Marionette(self.port)
        await session.connect(timeout=90.0)
        await session.new_session(page_timeout_ms=int(self.cfg.page_timeout_s * 1000))
        self._session = session

    async def probe(self, target: Target) -> dict:
        for attempt in (1, 2):
            if self._session is None:
                await self.restart()
            try:
                error, value = await self._session.visit(
                    target.url, timeout=self.cfg.page_timeout_s + PROCESS_GRACE_S
                )
            except MarionetteError as failure:
                await self.stop()
                if attempt == 2:
                    return verdicts.firefox_verdict(
                        {"error": "marionette", "message": str(failure)}, None, self.proto
                    )
                continue
            return verdicts.firefox_verdict(error, value, self.proto)
        return verdicts.firefox_verdict({"error": "marionette"}, None, self.proto)

    async def restart(self) -> None:
        await self.stop()
        await self.start()

    async def stop(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None
        process = self._process
        self._process = None
        if process is None or process.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), 15)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                process.kill()

    async def dispose(self) -> None:
        await self.stop()
        shutil.rmtree(self.profile, ignore_errors=True)
