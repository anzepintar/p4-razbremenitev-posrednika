#!/usr/bin/env python3
"""Zapise tabelo steering v stikalo P4: kateri odjemalec gre prek posrednika."""
from __future__ import annotations

import argparse
from pathlib import Path

import yaml

BUILD = Path("/opt/traffic/switch/build")
P4INFO = BUILD / "steering.p4info.txtpb"
BMV2_JSON = BUILD / "steering.json"
SCENARIO = Path("/opt/traffic/scenario.yml")

TABLE = "SwitchIngress.steering"
PORT_CLIENT = 1
ACTIONS = ("direct", "via_mitm")


class SteeringError(ValueError):
    pass


def load_plan(path: Path) -> dict[str, str]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    mapping = raw.get("steering") or {}

    unknown = set(mapping.values()) - set(ACTIONS)
    if unknown:
        raise SteeringError(f"neznane akcije {sorted(unknown)} v {path}")

    plan = {}
    for entry in raw["clients"]:
        trust = entry["trust"]
        if trust not in mapping:
            raise SteeringError(f"steering nima zaupanja '{trust}' za {entry['src_ip']}")
        plan[entry["src_ip"]] = mapping[trust]
    return plan


def write_entries(grpc_addr: str, plan: dict[str, str]) -> None:
    import p4runtime_sh.shell as sh

    sh.setup(
        device_id=0,
        grpc_addr=grpc_addr,
        election_id=(0, 1),
        config=sh.FwdPipeConfig(str(P4INFO), str(BMV2_JSON)),
    )
    try:
        # Vpisemo le pregledane odjemalce, 'direct' je privzeta akcija tabele.
        for src_ip in sorted(ip for ip, action in plan.items() if action == "via_mitm"):
            entry = sh.TableEntry(TABLE)(action="SwitchIngress.via_mitm")
            entry.match["standard_metadata.ingress_port"] = str(PORT_CLIENT)
            entry.match["hdr.ipv4.srcAddr"] = src_ip
            try:
                entry.insert()
            except Exception:
                entry.modify()
            print(f"steer: {src_ip} -> via_mitm", flush=True)
    finally:
        sh.teardown()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="steer")
    parser.add_argument("--grpc-addr", default="10.20.1.2:9559")
    parser.add_argument("--scenario", type=Path, default=SCENARIO)
    args = parser.parse_args(argv)

    plan = load_plan(args.scenario)
    write_entries(args.grpc_addr, plan)

    inspected = sum(1 for action in plan.values() if action == "via_mitm")
    print(f"steer: {inspected} od {len(plan)} odjemalcev prek posrednika", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
