#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

QUIC_SID = 2000000
DOMAIN = re.compile(r'content:"([^"]+)"')


def follow(path: Path, poll: float):
    while not path.is_file():
        time.sleep(poll)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(0, 2)
        while True:
            line = handle.readline()
            if line:
                yield line
            else:
                time.sleep(poll)


def load_domains(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    return {m.group(1) for m in DOMAIN.finditer(path.read_text(encoding="utf-8"))}


def as_alert(event: dict, domains: set[str]) -> dict | None:
    """Zaznava iz dogodka; Suricata 7 nima keyworda quic.sni, zato QUIC ujamemo iz dnevnika."""
    kind = event.get("event_type")
    if kind == "alert":
        alert = event.get("alert") or {}
        return {
            "sid": int(alert.get("signature_id") or 0),
            "signature": alert.get("signature"),
            "sni": (event.get("tls") or {}).get("sni"),
            "source": "rule",
        }

    if kind == "quic":
        sni = (event.get("quic") or {}).get("sni")
        if sni and sni in domains:
            return {
                "sid": QUIC_SID,
                "signature": f"phishing SNI {sni}",
                "sni": sni,
                "source": "quic-sni",
            }
    return None


def post(url: str, payload: dict, timeout: float) -> str | None:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, headers={"content-type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout):
            return None
    except (urllib.error.URLError, OSError) as failure:
        return str(failure)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="alert_forward")
    parser.add_argument("--eve", type=Path, default=Path("/opt/traffic/out/eve.json"))
    parser.add_argument("--log", type=Path, default=Path("/opt/traffic/out/alerts.jsonl"))
    parser.add_argument("--rules", type=Path, default=Path("/opt/traffic/ids/testset.rules"))
    parser.add_argument("--url", default="http://10.20.2.1:8080/alert")
    parser.add_argument("--dedup", type=float, default=10.0)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--poll", type=float, default=0.2)
    args = parser.parse_args(argv)

    args.log.parent.mkdir(parents=True, exist_ok=True)
    domains = load_domains(args.rules)
    seen: dict[tuple[str, str], float] = {}
    print(f"alert_forward: {args.eve} -> {args.url}, {len(domains)} domen", flush=True)

    with args.log.open("a", encoding="utf-8") as sink:
        for line in follow(args.eve, args.poll):
            try:
                event = json.loads(line)
            except ValueError:
                continue

            found = as_alert(event, domains)
            if found is None:
                continue

            src = event.get("src_ip") or ""
            now = time.monotonic()
            key = (src, found["sni"] or str(found["sid"]))
            if now - seen.get(key, -args.dedup) < args.dedup:
                continue
            seen[key] = now

            payload = {
                "src_ip": src,
                "dest_ip": event.get("dest_ip"),
                "proto": event.get("proto"),
                "ts": event.get("timestamp"),
                **found,
            }
            payload["error"] = post(args.url, payload, args.timeout)
            sink.write(json.dumps(payload, ensure_ascii=False) + "\n")
            sink.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
