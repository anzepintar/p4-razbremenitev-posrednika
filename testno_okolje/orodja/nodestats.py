#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

NODES = ("client", "switch", "mitm", "server")
CPU_KEYS = ("usage_usec", "user_usec", "system_usec")
CGROUP = "/sys/fs/cgroup"


def containers(topo: str) -> list[str]:
    names = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True
    ).stdout.split()
    return [f"clab-{topo}-{node}" for node in NODES if f"clab-{topo}-{node}" in names]


def read(container: str, path: str) -> str:
    try:
        return subprocess.run(
            ["docker", "exec", container, "cat", path],
            capture_output=True, text=True, timeout=20, check=True,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return ""


def cpu_quota(container: str) -> float:
    parts = read(container, f"{CGROUP}/cpu.max").split()
    if len(parts) == 2 and parts[0] != "max" and parts[1].isdigit():
        return round(int(parts[0]) / int(parts[1]), 3)
    return float(os.cpu_count() or 1)


def cpu_stats(container: str) -> dict:
    values: dict[str, float] = {}
    for line in read(container, f"{CGROUP}/cpu.stat").splitlines():
        name, _, number = line.partition(" ")
        if name in CPU_KEYS and number.strip().isdigit():
            values[name] = int(number)
    memory = read(container, f"{CGROUP}/memory.current").strip()
    if memory.isdigit():
        values["mem_bytes"] = int(memory)
    values["cpu_quota"] = cpu_quota(container)
    return values


def link_stats(container: str) -> dict:
    try:
        links = json.loads(subprocess.run(
            ["docker", "exec", container, "ip", "-s", "-j", "link"],
            capture_output=True, text=True, timeout=20, check=True,
        ).stdout)
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


def snapshot(topo: str, target: Path, reader) -> int:
    out = {node_of(name): reader(name) for name in containers(topo)}
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("uporaba: nodestats.py <links|cpu> <postavitev> <cilj>", file=sys.stderr)
        return 2
    mode, topo, target = argv[1], argv[2], Path(argv[3])
    readers = {"links": link_stats, "cpu": cpu_stats}
    if mode not in readers:
        print(f"nodestats.py: neznan nacin '{mode}'", file=sys.stderr)
        return 2
    return snapshot(topo, target, readers[mode])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
