#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import NamedTuple
from urllib.parse import parse_qs, urlparse

import yaml

BUILD = Path("/opt/traffic/switch/build")
P4INFO = BUILD / "steering.p4info.txtpb"
BMV2_JSON = BUILD / "steering.json"

TABLE = "SwitchIngress.steering"
PORT_CLIENT = 1
PORT_SERVER = 2
PORT_IDS = 4
MITM_MAC = "00:00:00:00:03:0a"
MITM_GW_MAC = "00:00:00:00:03:fe"
MIRROR_SESSION = 100

ACTIONS = ("direct", "via_mitm", "mirror")
INSPECTED = ("via_mitm",)


class PolicyError(ValueError):
    pass


class Policy(NamedTuple):
    mapping: dict[str, str]
    clients: dict[str, str]
    servers: list[str]
    levels: list[str]


def load_policy(path: Path, name: str) -> Policy:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))

    policies = raw.get("policy") or {}
    if name not in policies:
        raise PolicyError(f"politike '{name}' ni v {path}, na voljo so {sorted(policies)}")
    mapping = policies[name]

    unknown = set(mapping.values()) - set(ACTIONS)
    if unknown:
        raise PolicyError(f"politika '{name}': neznane akcije {sorted(unknown)}")

    clients = {entry["src_ip"]: entry["trust"] for entry in raw["clients"]}
    missing = {trust for trust in clients.values() if trust not in mapping}
    if missing:
        raise PolicyError(f"politika '{name}': manjka zaupanje {sorted(missing)}")

    levels = list(raw.get("trust_levels") or [])
    off_ladder = (set(clients.values()) | set(mapping)) - set(levels)
    if off_ladder:
        raise PolicyError(f"trust_levels ne vsebuje {sorted(off_ladder)}")

    servers = list((raw.get("testset") or {}).get("ips") or [])
    return Policy(mapping, clients, servers, levels)


class Log:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._lock = threading.Lock()

    def write(self, **row) -> None:
        row["ts"] = round(time.time(), 6)
        with self._lock, self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


class Steering:
    def __init__(self, grpc_addr: str | None) -> None:
        self.entries: dict[str, str] = {}
        self._lock = threading.Lock()
        self._sh = None
        self._cloned = False

        if not grpc_addr:
            return

        import p4runtime_sh.shell as sh

        sh.setup(
            device_id=0,
            grpc_addr=grpc_addr,
            election_id=(0, 1),
            config=sh.FwdPipeConfig(str(P4INFO), str(BMV2_JSON)),
        )
        self._sh = sh

    def apply(self, src_ip: str, action: str, port: int = PORT_CLIENT) -> None:
        with self._lock:
            self.entries[f"{port}:{src_ip}"] = action
            if self._sh is not None:
                if action == "mirror":
                    self._clone_session()
                self._write(src_ip, action, port)

    def _clone_session(self) -> None:
        if self._cloned:
            return
        session = self._sh.CloneSessionEntry(MIRROR_SESSION)
        session.add(PORT_IDS)
        try:
            session.insert()
        except Exception:
            session.modify()
        self._cloned = True

    def _write(self, src_ip: str, action: str, port: int) -> None:
        sh = self._sh
        entry = sh.TableEntry(TABLE)(action=f"SwitchIngress.{action}")
        entry.match["standard_metadata.ingress_port"] = str(port)
        entry.match["hdr.ipv4.srcAddr"] = src_ip

        if action == "via_mitm":
            entry.action["dmac"] = MITM_MAC
            entry.action["smac"] = MITM_GW_MAC
        elif action == "mirror":
            entry.action["session"] = str(MIRROR_SESSION)

        try:
            entry.insert()
        except Exception:
            entry.modify()

    def teardown(self) -> None:
        if self._sh is not None:
            self._sh.teardown()


class Handler(BaseHTTPRequestHandler):
    controller: Controller

    def do_GET(self) -> None:
        url = urlparse(self.path)
        if url.path == "/decide":
            src = (parse_qs(url.query).get("src") or [""])[0]
            self._json(self.controller.decide(src))
        elif url.path == "/state":
            self._json(self.controller.state())
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/alert":
            self.send_error(404)
            return
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else "{}"
        self._json(self.controller.alert(body))

    def _json(self, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:
        pass


class Controller:
    def __init__(self, policy: dict[str, str], clients: dict[str, str],
                 steering: Steering, log: Log, name: str,
                 servers: list[str] | None = None,
                 levels: list[str] | None = None) -> None:
        self.policy = policy
        self.clients = clients
        self.steering = steering
        self.log = log
        self.name = name
        self.servers = servers or []
        self.levels = levels or []
        self._demote_lock = threading.Lock()

    def action_for(self, src_ip: str) -> str:
        trust = self.clients.get(src_ip)
        return self.policy.get(trust, "via_mitm")

    def bootstrap(self) -> None:
        for src_ip, trust in sorted(self.clients.items()):
            started = time.perf_counter()
            action = self.policy[trust]
            self.steering.apply(src_ip, action)
            self.log.write(source="bootstrap", src=src_ip, trust=trust, action=action,
                           handle_ms=round((time.perf_counter() - started) * 1000, 4))

        # Zrcalimo obe smeri, sicer Suricata vidi le polovico toka. Vnosi v smeri
        # streznika so skupni vsem odjemalcem, zato so vezani na naslov streznika.
        if "mirror" not in self.policy.values():
            return
        for src_ip in sorted(self.servers):
            started = time.perf_counter()
            self.steering.apply(src_ip, "mirror", port=PORT_SERVER)
            self.log.write(source="bootstrap", src=src_ip, trust=None, action="mirror",
                           port=PORT_SERVER,
                           handle_ms=round((time.perf_counter() - started) * 1000, 4))

    def decide(self, src_ip: str) -> dict:
        started = time.perf_counter()
        action = self.action_for(src_ip)
        inspect = src_ip not in self.clients or action in INSPECTED
        handle_ms = round((time.perf_counter() - started) * 1000, 4)
        self.log.write(source="decide", src=src_ip, trust=self.clients.get(src_ip),
                       action="inspect" if inspect else "direct", handle_ms=handle_ms)
        return {"action": "inspect" if inspect else "direct", "handle_ms": handle_ms}

    def demote(self, src_ip: str) -> dict:
        with self._demote_lock:
            before = self.clients.get(src_ip)
            if before is None or before not in self.levels:
                return {"changed": False, "trust_before": before, "trust_after": before,
                        "action_before": None, "action_after": None}

            index = min(self.levels.index(before) + 1, len(self.levels) - 1)
            after = self.levels[index]
            action_before = self.policy[before]
            action_after = self.policy[after]

            self.clients[src_ip] = after
            if action_after != action_before:
                self.steering.apply(src_ip, action_after)
            return {"changed": action_after != action_before,
                    "trust_before": before, "trust_after": after,
                    "action_before": action_before, "action_after": action_after}

    def alert(self, body: str) -> dict:
        started = time.perf_counter()
        try:
            payload = json.loads(body)
        except ValueError:
            payload = {"raw": body}

        src = payload.get("src_ip") or ""
        result = self.demote(src)
        self.log.write(source="demote", src=src, sid=payload.get("sid"),
                       sni=payload.get("sni"), detected_by=payload.get("source"),
                       alert_ts=payload.get("ts"),
                       reaction_ms=round((time.perf_counter() - started) * 1000, 4),
                       **result)
        return {"ok": True, **result}

    def state(self) -> dict:
        return {
            "policy": self.name,
            "mapping": self.policy,
            "levels": self.levels,
            "clients": self.clients,
            "entries": self.steering.entries,
        }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="controller")
    parser.add_argument("--scenario", type=Path, default=Path("/opt/traffic/scenario.yml"))
    parser.add_argument("--policy", default="mitm")
    parser.add_argument("--grpc-addr", default=None)
    parser.add_argument("--listen", default="0.0.0.0:8080")
    parser.add_argument("--log", type=Path, default=Path("/opt/traffic/out/controller.jsonl"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    policy = load_policy(args.scenario, args.policy)

    steering = Steering(args.grpc_addr)
    controller = Controller(policy.mapping, policy.clients, steering, Log(args.log),
                            args.policy, policy.servers, policy.levels)
    controller.bootstrap()

    host, _, port = args.listen.rpartition(":")
    Handler.controller = controller
    server = ThreadingHTTPServer((host, int(port)), Handler)
    print(f"controller: politika '{args.policy}', {len(policy.clients)} odjemalcev, {args.listen}",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        steering.teardown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
