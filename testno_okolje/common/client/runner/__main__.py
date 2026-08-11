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
    parser.add_argument("--config", default="/opt/traffic/scenario.yml")
    parser.add_argument("--duration", type=float, default=None)
    parser.add_argument("--requests", type=int, default=None)
    parser.add_argument("--speed", type=float, default=1.0)
    parser.add_argument("--parallel", type=int, default=1)
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


def pick_protocol(rng: random.Random, weights: dict[str, float]) -> str:
    items = sorted(weights.items())
    draw = rng.random()
    cumulative = 0.0
    for name, weight in items:
        cumulative += weight
        if draw < cumulative:
            return name
    return items[-1][0]


def build_request(
    scenario: scenario_mod.Scenario,
    profile: scenario_mod.Profile,
    rng: random.Random,
) -> tuple[curlrun.Request, str, bool]:
    label = rng.choice(profile.labels)
    domain = rng.choice([s.domain for s in scenario.by_label(label)])
    proto = pick_protocol(rng, profile.protocols)
    fronted = rng.random() < profile.fronting_share

    if fronted:
        hidden = (
            domain
            if label == "mal"
            else rng.choice([s.domain for s in scenario.by_label("mal")])
        )
        cover_pool = [
            site.domain
            for site in scenario.by_label("ben")
            if site.ip == scenario.sites[hidden].ip
        ] or [site.domain for site in scenario.by_label("ben")]
        cover = rng.choice(cover_pool)
        targets = (urls.Target(domain=cover, path=scenario_mod.INDEX),)
        request = curlrun.Request(targets=targets, proto=proto, host_header=hidden)
        return request, hidden, True

    request = curlrun.Request(targets=tuple(urls.page_targets(scenario, domain)), proto=proto)
    return request, domain, False


async def run_client(
    scenario: scenario_mod.Scenario,
    client: scenario_mod.Client,
    index: int,
    writer: MetricsWriter,
    args: argparse.Namespace,
    deadline: float | None,
    max_requests: int | None,
) -> None:
    profile = scenario.profile_for(client)
    rng = random.Random(scenario.run.seed + index)
    speed = max(args.speed, 0.01)
    min_interval = 1.0 / (profile.rate * speed)
    done = 0

    while True:
        if max_requests is not None and done >= max_requests:
            return
        if deadline is not None and time.monotonic() >= deadline:
            return

        request, page_domain, fronted = build_request(scenario, profile, rng)
        think = rng.uniform(*profile.think_time) / speed
        started = time.monotonic()

        argv = curlrun.build_argv(scenario, request, src_ip=client.src_ip,
                                  cacert=str(scenario.run.cacert))
        stdout = await _run(argv)

        labels = {
            "ts": round(time.time(), 6),
            "client": client.id,
            "trust": client.trust,
            "profile": profile.name,
            "page": page_domain,
            "proto": request.proto,
            "fronting": fronted,
            "sni": request.targets[0].domain,
            "authority": request.host_header or request.targets[0].domain,
        }
        rows = [
            curlrun.to_metric(record, labels={**labels, **_target_labels(scenario, record)})
            for record in curlrun.parse_output(stdout)
        ]
        await writer.write(rows)
        done += 1

        # `rate` je zgornja meja, `think_time` nakljucni dodatek.
        elapsed = time.monotonic() - started
        await asyncio.sleep(max(0.0, min_interval - elapsed) + think)


def _target_labels(scenario: scenario_mod.Scenario, record: dict) -> dict:
    # Kategorijo doloci domena, ki jo je streznik dejansko postregel.
    domain = record.get("x_domain") or ""
    site = scenario.sites.get(domain)
    return {"domain": domain or None, "category": site.category if site else None}


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
    scenario = scenario_mod.load(args.config)
    wait_for_cacert(scenario.run.cacert)

    duration = args.duration if args.duration is not None else scenario.run.duration
    deadline = None if args.requests else time.monotonic() + duration

    writer = MetricsWriter(scenario.run.out / "metrics.jsonl")
    parallel = max(args.parallel, 1)
    count = len(scenario.clients)
    try:
        await asyncio.gather(
            *(
                run_client(scenario, client, worker * count + position,
                           writer, args, deadline, args.requests)
                for position, client in enumerate(scenario.clients)
                for worker in range(parallel)
            )
        )
    finally:
        writer.close()

    summary = {
        "total": summarize.stats(writer.rows),
        "speed": args.speed,
        "parallel": parallel,
        "concurrency": count * parallel,
    }
    (scenario.run.out / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary["total"], ensure_ascii=False))
    return 0 if summary["total"]["requests"] else 1


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(main_async(parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())
