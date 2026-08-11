#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

CLIENTS = "10.0.1.0/24"


def docker(*argv: str) -> str:
    return subprocess.run(["docker", "exec", *argv], capture_output=True, text=True,
                          timeout=20, check=True).stdout


def link_stats(container: str) -> dict | None:
    try:
        stats = json.loads(docker(container, "ip", "-s", "-j", "link", "show", "eth1"))[0]["stats64"]
    except (subprocess.SubprocessError, ValueError, IndexError, KeyError):
        return None
    return {
        "rx_packets": stats["rx"]["packets"],
        "rx_bytes": stats["rx"]["bytes"],
        "tx_packets": stats["tx"]["packets"],
        "tx_bytes": stats["tx"]["bytes"],
    }


def counted(container: str, chain: str) -> dict | None:
    try:
        raw = docker(container, "iptables", "-nvx", "-L", chain)
    except subprocess.SubprocessError:
        return None
    # Pravilo brez akcije pusti stolpec 'target' prazen, zato se na fiksne indekse ni
    # mogoce zanesti; stevca sta vedno prvi dve polji vrstice z naslovom odjemalcev.
    for line in raw.splitlines():
        parts = line.split()
        if CLIENTS in parts and parts[0].isdigit():
            return {"packets": int(parts[0]), "bytes": int(parts[1])}
    return None


def main(topo: str, target: str) -> int:
    out = {}
    for node in ("client", "mitm"):
        stats = link_stats(f"clab-{topo}-{node}")
        if stats:
            out[node] = stats

    if "mitm" in out:
        proxy = f"clab-{topo}-mitm"
        out["intercepted"] = counted(proxy, "INPUT")
        out["passthrough"] = counted(proxy, "FORWARD")

    Path(target).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
