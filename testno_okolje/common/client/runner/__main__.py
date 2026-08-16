from __future__ import annotations

import argparse
import asyncio
import json
import random
import time
from pathlib import Path

from . import curlrun, scenario as scenario_mod, summarize, urls

CACERT_WAIT = 60.0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="runner")
    parser.add_argument("--config", default="/opt/traffic/experiment.yml")
    parser.add_argument("--duration", type=float, default=None)
    parser.add_argument("--requests", type=int, default=None)
    parser.add_argument("--quic-share", type=float, default=0.0)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--rate-mbps", type=float, default=None)
    parser.add_argument("--rate-rps", type=float, default=None)
    parser.add_argument("--groups", default=None)
    parser.add_argument("--label", default=None)
    parser.add_argument("--src-ip", default=None)
    return parser.parse_args(argv)


class MetricsWriter:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = path.open("w", encoding="utf-8")
        self._lock = asyncio.Lock()
        self.rows: list[dict] = []

    async def write(self, rows: list[dict]) -> None:
        async with self._lock:
            for row in rows:
                self._handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                self.rows.append(row)
            self._handle.flush()

    def close(self) -> None:
        self._handle.close()


class BytePacer:

    def __init__(self, rate_mbps: float | None) -> None:
        self.target_bps = (rate_mbps * 1e6) if rate_mbps else None
        self.started = time.monotonic()
        self.sent = 0
        self._lock = asyncio.Lock()

    async def account(self, size: int) -> None:
        if self.target_bps is None:
            return
        async with self._lock:
            self.sent += size
            elapsed = time.monotonic() - self.started
            needed = self.sent * 8 / self.target_bps
            delay = needed - elapsed
        if delay > 0:
            await asyncio.sleep(delay)

    @property
    def achieved_mbps(self) -> float | None:
        elapsed = time.monotonic() - self.started
        return round(self.sent * 8 / elapsed / 1e6, 2) if elapsed > 0 else None


class RequestPacer:
    def __init__(self, rate_rps: float | None) -> None:
        self.target_rps = rate_rps
        self.started = time.monotonic()
        self.done = 0
        self._lock = asyncio.Lock()

    async def account(self) -> None:
        async with self._lock:
            self.done += 1
            if self.target_rps is None:
                return
            elapsed = time.monotonic() - self.started
            delay = self.done / self.target_rps - elapsed
        if delay > 0:
            await asyncio.sleep(delay)

    @property
    def achieved_rps(self) -> float | None:
        elapsed = time.monotonic() - self.started
        return round(self.done / elapsed, 2) if elapsed > 0 else None


def build_request(
    scenario: scenario_mod.Scenario, rng: random.Random, pool: list[str]
) -> tuple[curlrun.Request, str]:
    domain = rng.choice(pool)
    proto = "h3" if rng.random() < scenario.quic_share else "h2"
    targets = tuple(urls.page_targets(scenario, domain))
    return curlrun.Request(targets=targets, proto=proto), domain


async def run_worker(
    scenario: scenario_mod.Scenario,
    index: int,
    writer: MetricsWriter,
    pacer: BytePacer,
    rate: RequestPacer,
    pool: list[str],
    args: argparse.Namespace,
    deadline: float | None,
    max_requests: int | None,
    counter: dict,
) -> None:
    rng = random.Random(scenario.run.seed + index)

    while True:
        if max_requests is not None and counter["done"] >= max_requests:
            return
        if deadline is not None and time.monotonic() >= deadline:
            return

        request, page = build_request(scenario, rng, pool)
        site = scenario.sites[page]

        argv = curlrun.build_argv(
            scenario, request, src_ip=args.src_ip, cacert=str(scenario.run.cacert)
        )
        stdout = await _run(argv)

        labels = {
            "ts": round(time.time(), 6),
            "worker": index,
            "page": page,
            "group": site.group,
            "server_ip": site.ip,
            "expect_blocked": site.expect_blocked,
            "proto": request.proto,
        }
        document = request.targets[0].url
        rows = [
            curlrun.to_metric(
                record,
                labels={**labels,
                        "document": (record.get("curl", {}).get("url_effective") == document)},
            )
            for record in curlrun.parse_output(stdout)
        ]
        await writer.write(rows)
        counter["done"] += 1
        await pacer.account(sum(row.get("size_download") or 0 for row in rows))
        await rate.account()


async def _run(argv: list[str]) -> str:
    process = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
    )
    stdout, _ = await process.communicate()
    return stdout.decode("utf-8", "replace")


def wait_for_cacert(path: Path) -> None:
    deadline = time.monotonic() + CACERT_WAIT
    while time.monotonic() < deadline:
        if path.is_file() and path.stat().st_size > 0:
            return
        time.sleep(0.5)
    raise SystemExit(f"CA '{path}' se ni pojavil v {CACERT_WAIT:.0f}s - ali streznik tece?")


async def main_async(args: argparse.Namespace) -> int:
    scenario = scenario_mod.load(args.config, quic_share=args.quic_share)
    wait_for_cacert(scenario.run.cacert)

    duration = args.duration if args.duration is not None else scenario.run.duration
    deadline = None if args.requests else time.monotonic() + duration

    groups = [g.strip() for g in args.groups.split(",")] if args.groups else None
    try:
        pool = scenario.domains_in(groups) if groups else scenario.domains()
    except scenario_mod.ScenarioError as error:
        raise SystemExit(f"runner: {error}")

    suffix = f"_{args.label}" if args.label else ""
    writer = MetricsWriter(scenario.run.out / f"metrics{suffix}.jsonl")
    pacer = BytePacer(args.rate_mbps)
    rate = RequestPacer(args.rate_rps)
    counter = {"done": 0}
    workers = max(args.workers, 1)
    try:
        await asyncio.gather(
            *(
                run_worker(scenario, index, writer, pacer, rate, pool, args,
                           deadline, args.requests, counter)
                for index in range(workers)
            )
        )
    finally:
        writer.close()

    summary = {
        "total": summarize.stats(writer.rows),
        "by_group": summarize.by_group(writer.rows),
        "quic_share": args.quic_share,
        "groups": groups,
        "rate_target_mbps": args.rate_mbps,
        "rate_achieved_mbps": pacer.achieved_mbps,
        "rate_target_rps": args.rate_rps,
        "rate_achieved_rps": rate.achieved_rps,
        "workers": workers,
        "duration_s": duration,
    }
    (scenario.run.out / f"summary{suffix}.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps({k: summary[k] for k in
                      ("rate_target_mbps", "rate_achieved_mbps",
                       "rate_target_rps", "rate_achieved_rps", "quic_share")},
                     ensure_ascii=False))
    print(json.dumps(summary["total"], ensure_ascii=False))
    return 0 if summary["total"]["requests"] else 1


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(main_async(parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())
