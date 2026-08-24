"""Pregled nabora domen z enim odjemalcem in enim protokolom.

Program tece v vsebniku odjemalca, tako kot runner. Vsak klic pokrije en blok, torej
en odjemalec in en protokol, ker gostitelj med bloki prebere stevce stikala in mora
zato vedeti, kateri promet je blok povzrocil.

    python3 -m probe --mode discover --domains domene.json --out cilji.json
    python3 -m probe --client curl --proto h2 --targets cilji.json --out probes.jsonl
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from common import Writer, drain

from . import verdicts
from .clients import Config, FirefoxWorker, Target, follow, probe_chromium, probe_curl, row

PROBES = {"curl": probe_curl, "chromium": probe_chromium}
DEFAULT_JOBS = {"curl": 8, "chromium": 4, "firefox": 4}

RETRY_PAUSE_S = 2.0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="probe")
    parser.add_argument("--mode", choices=("probe", "discover"), default="probe")
    parser.add_argument("--client", choices=verdicts.CLIENTS)
    parser.add_argument("--proto", choices=verdicts.PROTOCOLS)
    parser.add_argument("--domains", type=Path)
    parser.add_argument("--targets", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--phase", default="")
    parser.add_argument("--jobs", type=int, default=None)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--connect-timeout", type=float, default=5.0)
    parser.add_argument("--max-time", type=float, default=20.0)
    parser.add_argument("--page-timeout", type=float, default=30.0)
    parser.add_argument("--cacert", default=None)
    parser.add_argument("--restart-every", type=int, default=25)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--no-kyber", action="store_true")
    args = parser.parse_args(argv)

    if args.mode == "probe" and not (args.client and args.proto and args.targets):
        parser.error("pregled potrebuje --client, --proto in --targets")
    if args.mode == "discover" and not args.domains:
        parser.error("iskanje koncnih gostiteljev potrebuje --domains")
    return args


def load_targets(path: Path, limit: int) -> list[Target]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data["targets"] if isinstance(data, dict) else data
    targets = [Target.from_dict(item) for item in items if item.get("reachable", True)]
    return targets[:limit] if limit else targets


def load_domains(path: Path, limit: int) -> list[Target]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data["domains"] if isinstance(data, dict) else data
    targets = [Target.from_dict(item) for item in items]
    return targets[:limit] if limit else targets


async def with_retry(probe, retries: int, pause: float = RETRY_PAUSE_S) -> dict:
    """Neuspeh se ponovi; stevilo poskusov gre v vrstico, da je raztros omrezja
    lociljiv od resnicne okvare."""
    verdict = await probe()
    tries = 1
    while not verdict.get("ok") and tries <= max(0, retries):
        await asyncio.sleep(pause)
        verdict = await probe()
        tries += 1
    verdict["attempts"] = tries
    return verdict


class Progress:
    def __init__(self, label: str, total: int) -> None:
        self.label, self.total, self.done, self.ok = label, total, 0, 0
        self.started = time.monotonic()

    def step(self, ok: bool) -> None:
        self.done += 1
        self.ok += bool(ok)
        if self.done % 10 == 0 or self.done == self.total:
            print(f"{self.label}: {self.done}/{self.total}, deluje {self.ok}",
                  flush=True)

    def summary(self) -> str:
        return (f"{self.label}: deluje {self.ok} od {self.done}, "
                f"{time.monotonic() - self.started:.0f}s")


async def sweep(args: argparse.Namespace, targets: list[Target], cfg: Config) -> Progress:
    writer = Writer(args.out)
    progress = Progress(f"{args.client} {args.proto}", len(targets))
    queue: "asyncio.Queue[Target]" = asyncio.Queue()
    for target in targets:
        queue.put_nowait(target)

    async def attempt(probe, target: Target) -> None:
        started_wall, started = time.time(), time.monotonic()
        verdict = await with_retry(lambda: probe(target), args.retries)
        await writer.write({"phase": args.phase,
                            **row(target, args.client, args.proto, verdict,
                                  ts=started_wall,
                                  elapsed_ms=(time.monotonic() - started) * 1000)})
        progress.step(bool(verdict.get("ok")))

    async def simple_worker() -> None:
        probe = PROBES[args.client]
        for target in drain(queue):
            await attempt(lambda item: probe(item, args.proto, cfg), target)

    async def browser_worker(index: int, hosts: list[str]) -> None:
        worker = FirefoxWorker(index, args.proto, hosts, cfg)
        seen = 0
        try:
            await worker.start()
            for target in drain(queue):
                if seen and args.restart_every and seen % args.restart_every == 0:
                    await worker.restart()
                seen += 1
                await attempt(worker.probe, target)
        finally:
            await worker.dispose()

    jobs = max(1, args.jobs or DEFAULT_JOBS[args.client])
    if args.client == "firefox":
        hosts = sorted({target.host for target in targets})
        workers = [browser_worker(index, hosts) for index in range(jobs)]
    else:
        workers = [simple_worker() for _ in range(jobs)]

    try:
        for outcome in await asyncio.gather(*workers, return_exceptions=True):
            if isinstance(outcome, BaseException):
                print(f"  delavec je odpovedal: {outcome}", file=sys.stderr)
    finally:
        writer.close()
    return progress


async def discover(args: argparse.Namespace, targets: list[Target], cfg: Config) -> int:
    """Korak 0: kam apex domena pripelje. Ce ne odgovori, se poskusi se www."""
    found: list[dict] = []
    progress = Progress("iskanje koncnih gostiteljev", len(targets))
    queue: "asyncio.Queue[Target]" = asyncio.Queue()
    for target in targets:
        queue.put_nowait(target)
    lock = asyncio.Lock()

    async def worker() -> None:
        for target in drain(queue):
            result = await follow(target, cfg)
            via = "apex"
            if not result["ok"] and not target.domain.startswith("www."):
                fallback = Target(target.rank, target.domain, f"www.{target.domain}",
                                  f"https://www.{target.domain}/", target.categories)
                retry = await follow(fallback, cfg)
                if retry["ok"]:
                    result, via = retry, "www"
            url = verdicts.origin_of(result.get("url_effective") or "") or target.url
            async with lock:
                found.append({
                    "rank": target.rank,
                    "domain": target.domain,
                    "categories": target.categories,
                    "reachable": bool(result["ok"]),
                    "via": via if result["ok"] else None,
                    "host": verdicts.host_of(url),
                    "url": url,
                    "http_code": result.get("http_code"),
                    "error": result.get("error"),
                    "message": result.get("message"),
                })
            progress.step(bool(result["ok"]))

    await asyncio.gather(*(worker() for _ in range(max(1, args.jobs or 8))))

    found.sort(key=lambda item: item["rank"])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps({"targets": found}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    redirected = sum(1 for item in found if item["reachable"]
                     and item["host"] != item["domain"])
    print(f"{progress.summary()}, od tega {redirected} preusmerjenih na drugega "
          f"gostitelja", flush=True)
    return 0


async def main_async(args: argparse.Namespace) -> int:
    cfg = Config(connect_timeout_s=args.connect_timeout, max_time_s=args.max_time,
                 page_timeout_s=args.page_timeout, cacert=args.cacert,
                 no_kyber=args.no_kyber)

    if args.mode == "discover":
        return await discover(args, load_domains(args.domains, args.limit), cfg)

    targets = load_targets(args.targets, args.limit)
    if not targets:
        print("probe: v ciljih ni nobene dosegljive domene", file=sys.stderr)
        return 1
    progress = await sweep(args, targets, cfg)
    print(progress.summary(), flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(main_async(parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())
