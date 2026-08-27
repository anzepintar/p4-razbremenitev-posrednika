#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path

BUILD = Path("/opt/traffic/switch/build")
P4INFO = BUILD / "usmerjanje.p4info.txtpb"
BMV2_JSON = BUILD / "usmerjanje.json"
COMMON = Path("/opt/traffic")

sys.path.insert(0, str(COMMON))

import counters
import sni as sni_lists

SNI_TABLE = "SwitchIngress.sni_policy"
IP_TABLE = "SwitchIngress.ip_policy"
COUNTER = "SwitchIngress.stats"
STATS = counters.NAMES


def connect(grpc_addr: str, push_config: bool):
    import p4runtime_sh.shell as sh

    config = sh.FwdPipeConfig(str(P4INFO), str(BMV2_JSON)) if push_config else None
    sh.setup(device_id=0, grpc_addr=grpc_addr, election_id=(0, 1), config=config)
    return sh


@contextlib.contextmanager
def quiet():
    with contextlib.redirect_stdout(io.StringIO()):
        yield


def write_entries(sh, domains: dict[str, list[str]], ips: dict[str, list[str]]) -> None:
    for name, action in (("black", "sni_block"), ("white", "sni_white")):
        for pattern in domains[name]:
            _, _, priority = sni_lists.entry(pattern)
            with quiet():
                entry = sh.TableEntry(SNI_TABLE)(action=f"SwitchIngress.{action}")
                entry.match["meta.sni"] = sni_lists.match(pattern)
                entry.priority = priority
                try:
                    entry.insert()
                except Exception:
                    entry.modify()

    for name, action in (("black", "ip_block"), ("white", "ip_white")):
        for prefix in ips[name]:
            with quiet():
                entry = sh.TableEntry(IP_TABLE)(action=f"SwitchIngress.{action}")
                entry.match["hdr.ipv4.dstAddr"] = prefix
                try:
                    entry.insert()
                except Exception:
                    entry.modify()


def read_stats(sh) -> dict[str, int]:
    totals = dict.fromkeys(STATS, 0)
    for entry in sh.CounterEntry(COUNTER).read():
        index = entry.index
        if index < len(STATS):
            totals[STATS[index]] = entry.packet_count
    return totals


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="steer")
    parser.add_argument("--grpc-addr", default="10.20.1.2:9559")
    parser.add_argument("--lists", type=Path, default=sni_lists.DIR)
    parser.add_argument("--stats", type=Path)
    args = parser.parse_args(argv)

    if args.stats:
        sh = connect(args.grpc_addr, push_config=False)
        try:
            totals = read_stats(sh)
        finally:
            sh.teardown()
        args.stats.write_text(json.dumps(totals, indent=2) + "\n", encoding="utf-8")
        print(f"sni: {totals['sni_blocked']} od {totals['sni_seen']} zavrnjenih, "
              f"ip: {totals['ip_blocked']} zavrnjenih, "
              f"quic: {totals['quic_blocked']} od {totals['quic_sni']} zavrnjenih, "
              f"{totals['quic_white']} mimo posrednika, "
              f"{totals['quic']} na pregled, "
              f"drugo zavrnjeno: {totals['denied']}", flush=True)
        return 0

    domains = sni_lists.load("domain", args.lists)
    ips = sni_lists.load("ip", args.lists)

    sh = connect(args.grpc_addr, push_config=True)
    try:
        write_entries(sh, domains, ips)
    finally:
        sh.teardown()

    print(f"sni: {len(domains['black'])} crnih, {len(domains['white'])} belih domen", flush=True)
    print(f"ip:  {len(ips['black'])} crnih, {len(ips['white'])} belih naslovov", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
