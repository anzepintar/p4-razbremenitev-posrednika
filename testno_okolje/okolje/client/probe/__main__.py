"""Pregled nabora domen z enim odjemalcem in enim protokolom.

Program tece v vsebniku odjemalca, tako kot runner. Vsak klic pokrije en blok, torej
en odjemalec in en protokol, ker gostitelj med bloki prebere stevce stikala in mora
zato vedeti, kateri promet je blok povzrocil.

Nacin select pripravi nabor v dveh korakih: najprej poisce koncnega gostitelja apex
domene, nato pri vsakem dosegljivem preveri oba protokola brez prestrezanja. Vsak
protokol dobi svoj nabor, ker ju splet ne ponuja v enaki meri. Pregled iz nabora vzame
vzorec, ki ga doloca seme, in je pri vseh blokih isti.

    python3 -m probe --mode select --domains domene.json --out nabor.json \\
        --apex-out apex.json
    python3 -m probe --client curl --proto h2 --targets nabor.json --out probes.jsonl \\
        --sample 100 --seed 1234
"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
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
    parser.add_argument("--mode", choices=("probe", "select"), default="probe")
    parser.add_argument("--client", choices=verdicts.CLIENTS)
    parser.add_argument("--proto", choices=verdicts.PROTOCOLS)
    parser.add_argument("--domains", type=Path)
    parser.add_argument("--targets", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--apex-out", type=Path)
    parser.add_argument("--phase", default="")
    parser.add_argument("--jobs", type=int, default=None)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--sample", type=int, default=0)
    parser.add_argument("--seed", type=int, default=0)
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
    if args.mode == "select" and not args.domains:
        parser.error("izbor nabora potrebuje --domains")
    return args


def load_targets(path: Path, limit: int, proto: str | None = None,
                 sample: int = 0, seed: int = 0) -> list[Target]:
    """Cilji nabora. Vsak protokol ima svojo mnozico, zato je filter tu in ne v
    lupinskem programu; ista datoteka tako postreze oba pregleda.

    Vzorec je iz domen, ki delujejo po vseh protokolih, in ga doloca seme. Vsak blok
    ga izracuna sam, zato vsi bloki obeh postavitev pregledajo iste domene in so med
    seboj primerljivi.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    items = [item for item in (data["targets"] if isinstance(data, dict) else data)
             if item.get("reachable", True)]
    if sample:
        paired = sorted((item for item in items
                         if all((item.get(name) or {}).get("ok")
                                for name in verdicts.PROTOCOLS)),
                        key=lambda item: item["domain"])
        if len(paired) > sample:
            paired = random.Random(seed).sample(paired, sample)
        items = sorted(paired, key=lambda item: item["domain"])
    if proto:
        items = [item for item in items if (item.get(proto) or {}).get("ok")]
    targets = [Target.from_dict(item) for item in items]
    return targets[:limit] if limit else targets


def load_domains(path: Path, limit: int) -> tuple[dict, list[Target]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data["domains"] if isinstance(data, dict) else data
    meta = {key: data.get(key) for key in ("source", "captured")} \
        if isinstance(data, dict) else {}
    targets = [Target.from_dict(item) for item in items]
    return meta, (targets[:limit] if limit else targets)


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


async def apex_stage(args: argparse.Namespace, targets: list[Target],
                     cfg: Config) -> list[dict]:
    """Korak 1: kam apex domena pripelje. Ce ne odgovori, se poskusi se www."""
    found: list[dict] = []
    progress = Progress("korak 1, koncni gostitelji", len(targets))
    queue: "asyncio.Queue[Target]" = asyncio.Queue()
    for target in targets:
        queue.put_nowait(target)
    lock = asyncio.Lock()

    async def worker() -> None:
        for target in drain(queue):
            result = await follow(target, cfg)
            via = "apex"
            if not result["ok"] and not target.domain.startswith("www."):
                fallback = Target(target.domain, f"www.{target.domain}",
                                  f"https://www.{target.domain}/")
                retry = await follow(fallback, cfg)
                if retry["ok"]:
                    result, via = retry, "www"
            url = verdicts.origin_of(result.get("url_effective") or "") or target.url
            async with lock:
                found.append({
                    "domain": target.domain,
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
    found.sort(key=lambda item: item["domain"])
    redirected = sum(1 for item in found if item["reachable"]
                     and item["host"] != item["domain"])
    print(f"{progress.summary()}, od tega {redirected} preusmerjenih na drugega "
          f"gostitelja", flush=True)
    return found


async def protocol_stage(args: argparse.Namespace, targets: list[Target],
                         cfg: Config) -> dict[str, dict]:
    """Korak 2: ali koncni gostitelj postreze po posameznem protokolu, brez
    prestrezanja. Merilo je isti curl_verdict kot pri pregledu, zato se izbor in
    meritev ne moreta razhajati."""
    checks: dict[str, dict] = {}
    progress = Progress("korak 2, protokola brez prestrezanja",
                        len(targets) * len(verdicts.PROTOCOLS))
    queue: "asyncio.Queue[tuple[Target, str]]" = asyncio.Queue()
    for target in targets:
        for proto in verdicts.PROTOCOLS:
            queue.put_nowait((target, proto))
    lock = asyncio.Lock()

    async def worker() -> None:
        for target, proto in drain(queue):
            verdict = await with_retry(lambda: probe_curl(target, proto, cfg),
                                       args.retries)
            async with lock:
                checks.setdefault(target.domain, {})[proto] = {
                    "ok": bool(verdict.get("ok")),
                    "protocol": verdict.get("protocol"),
                    "ms": verdict.get("ms"),
                    "error": verdict.get("error"),
                    "message": verdict.get("message"),
                }
            progress.step(bool(verdict.get("ok")))

    await asyncio.gather(*(worker() for _ in range(max(1, args.jobs or 8))))
    print(progress.summary(), flush=True)
    return checks


def nabor(meta: dict, apex: list[dict], checks: dict[str, dict]) -> dict:
    """Nabor so dosegljive domene, pri katerih deluje vsaj en protokol. Blok stats
    je vir vseh delezev v porocilu, med njimi deleza domen s podporo za QUIC."""
    keys = ("domain", "host", "url", "reachable", "via")
    targets = []
    for item in apex:
        found = checks.get(item["domain"]) or {}
        if not item["reachable"] or not any(
                (found.get(proto) or {}).get("ok") for proto in verdicts.PROTOCOLS):
            continue
        targets.append({**{key: item[key] for key in keys}, **found})

    def counted(*wanted: str) -> int:
        return sum(1 for item in targets
                   if all((item.get(proto) or {}).get("ok") for proto in wanted))

    return {
        **meta,
        "stats": {
            "domains": len(apex),
            "reachable": sum(1 for item in apex if item["reachable"]),
            "h2": counted("h2"),
            "h3": counted("h3"),
            "both": counted("h2", "h3"),
            "h2_only": counted("h2") - counted("h2", "h3"),
            "h3_only": counted("h3") - counted("h2", "h3"),
            "selected": len(targets),
        },
        "targets": targets,
    }


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8")


async def select(args: argparse.Namespace, meta: dict, targets: list[Target],
                 cfg: Config) -> int:
    apex = await apex_stage(args, targets, cfg)
    if args.apex_out:
        write_json(args.apex_out, {**meta, "targets": apex})

    reachable = [Target.from_dict(item) for item in apex if item["reachable"]]
    checks = await protocol_stage(args, reachable, cfg) if reachable else {}
    picked = nabor(meta, apex, checks)
    write_json(args.out, picked)

    stats = picked["stats"]
    print(f"nabor: {stats['selected']} domen od {stats['domains']}, "
          f"dosegljivih {stats['reachable']}, HTTP/2 {stats['h2']}, "
          f"HTTP/3 {stats['h3']}, oba {stats['both']}", flush=True)
    return 0


async def main_async(args: argparse.Namespace) -> int:
    cfg = Config(connect_timeout_s=args.connect_timeout, max_time_s=args.max_time,
                 page_timeout_s=args.page_timeout, cacert=args.cacert,
                 no_kyber=args.no_kyber)

    if args.mode == "select":
        meta, targets = load_domains(args.domains, args.limit)
        return await select(args, meta, targets, cfg)

    targets = load_targets(args.targets, args.limit, args.proto,
                           sample=args.sample, seed=args.seed)
    if not targets:
        print(f"probe: v naboru ni nobene domene za {args.proto}", file=sys.stderr)
        return 1
    progress = await sweep(args, targets, cfg)
    print(progress.summary(), flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(main_async(parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())
