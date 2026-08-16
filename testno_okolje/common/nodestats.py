#!/usr/bin/env python3
from __future__ import annotations

import json
import signal
import subprocess
import sys
import time
from pathlib import Path

NODES = ("client", "switch", "mitm", "server")
INTERVAL = 1.0

_running = True


def stop(*_args) -> None:
    global _running
    _running = False


def containers(topo: str) -> list[str]:
    names = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True
    ).stdout.split()
    return [f"clab-{topo}-{node}" for node in NODES if f"clab-{topo}-{node}" in names]


def docker_stats(names: list[str]) -> dict[str, dict]:
    if not names:
        return {}
    out = subprocess.run(
        ["docker", "stats", "--no-stream", "--format",
         "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}", *names],
        capture_output=True, text=True, timeout=30,
    ).stdout

    found = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        name, cpu, mem, mempct = parts
        found[name] = {
            "cpu_pct": _number(cpu),
            "mem_mb": _mem_mb(mem),
            "mem_pct": _number(mempct),
        }
    return found


def _number(text: str) -> float | None:
    try:
        return float(text.strip().rstrip("%"))
    except ValueError:
        return None


def _mem_mb(text: str) -> float | None:
    used = text.split("/")[0].strip()
    for suffix, factor in (("GiB", 1024), ("MiB", 1), ("KiB", 1 / 1024), ("B", 1 / 1048576)):
        if used.endswith(suffix):
            value = _number(used[: -len(suffix)])
            return round(value * factor, 1) if value is not None else None
    return None


def link_stats(container: str) -> dict:
    try:
        raw = subprocess.run(
            ["docker", "exec", container, "ip", "-s", "-j", "link"],
            capture_output=True, text=True, timeout=20, check=True,
        ).stdout
        links = json.loads(raw)
    except (subprocess.SubprocessError, ValueError):
        return {}

    found = {}
    for link in links:
        name = link.get("ifname", "")
        stats = link.get("stats64")
        if not stats or name in ("lo", "eth0"):
            continue
        found[name] = {
            "rx_packets": stats["rx"]["packets"],
            "rx_bytes": stats["rx"]["bytes"],
            "tx_packets": stats["tx"]["packets"],
            "tx_bytes": stats["tx"]["bytes"],
        }
    return found


def node_of(container: str) -> str:
    return container.rsplit("-", 1)[-1]


def sample(topo: str, target: Path) -> int:
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    names = containers(topo)
    samples: list[dict] = []
    while _running:
        started = time.monotonic()
        reading = docker_stats(names)
        if reading:
            samples.append({
                "t": round(time.time(), 3),
                "nodes": {node_of(name): values for name, values in reading.items()},
            })
        time.sleep(max(0.0, INTERVAL - (time.monotonic() - started)))

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"samples": samples, "summary": summarise(samples)},
                                 indent=2) + "\n", encoding="utf-8")
    return 0


def summarise(samples: list[dict]) -> dict:
    per_node: dict[str, dict[str, list[float]]] = {}
    for entry in samples:
        for node, values in entry["nodes"].items():
            bucket = per_node.setdefault(node, {"cpu_pct": [], "mem_mb": []})
            for key in bucket:
                if values.get(key) is not None:
                    bucket[key].append(values[key])

    out = {}
    for node, bucket in sorted(per_node.items()):
        out[node] = {}
        for key, values in bucket.items():
            if not values:
                out[node][f"{key}_avg"] = out[node][f"{key}_max"] = None
                continue
            out[node][f"{key}_avg"] = round(sum(values) / len(values), 1)
            out[node][f"{key}_max"] = round(max(values), 1)
        out[node]["samples"] = len(bucket["cpu_pct"])
    return out


def links(topo: str, target: Path) -> int:
    out = {node_of(name): link_stats(name) for name in containers(topo)}
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("uporaba: nodestats.py <sample|links> <postavitev> <cilj>",
              file=sys.stderr)
        return 2
    mode, topo, target = argv[1], argv[2], Path(argv[3])
    if mode == "sample":
        return sample(topo, target)
    if mode == "links":
        return links(topo, target)
    print(f"nodestats.py: neznan nacin '{mode}'", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
