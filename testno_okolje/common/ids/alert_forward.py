#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

EVE = Path("/opt/traffic/out/eve.json")
LOG = Path("/opt/traffic/out/alerts.jsonl")
RULES = Path("/opt/traffic/ids/testset.rules")
URL = "http://10.20.2.1:8080/alert"

DEDUP = 10.0
TIMEOUT = 2.0
POLL = 0.2

QUIC_SID = 2000000
DOMAIN = re.compile(r'content:"([^"]+)"')


def follow(path: Path):
    while not path.is_file():
        time.sleep(POLL)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(0, 2)
        while True:
            line = handle.readline()
            if line:
                yield line
            else:
                time.sleep(POLL)


def load_domains(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    return {m.group(1) for m in DOMAIN.finditer(path.read_text(encoding="utf-8"))}


def as_alert(event: dict, domains: set[str]) -> dict | None:
    kind = event.get("event_type")
    if kind == "alert":
        alert = event.get("alert") or {}
        return {
            "sid": int(alert.get("signature_id") or 0),
            "signature": alert.get("signature"),
            "sni": (event.get("tls") or {}).get("sni"),
            "source": "rule",
        }

    # Suricata 7 nima keyworda quic.sni, zato QUIC ujamemo iz dogodka.
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


def post(payload: dict) -> str | None:
    request = urllib.request.Request(
        URL, data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT):
            return None
    except (urllib.error.URLError, OSError) as failure:
        return str(failure)


def main() -> int:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    domains = load_domains(RULES)
    seen: dict[tuple[str, str], float] = {}
    print(f"alert_forward: {EVE} -> {URL}, {len(domains)} domen", flush=True)

    with LOG.open("a", encoding="utf-8") as sink:
        for line in follow(EVE):
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
            if now - seen.get(key, -DEDUP) < DEDUP:
                continue
            seen[key] = now

            payload = {
                "src_ip": src,
                "dest_ip": event.get("dest_ip"),
                "proto": event.get("proto"),
                "ts": event.get("timestamp"),
                **found,
            }
            payload["error"] = post(payload)
            sink.write(json.dumps(payload, ensure_ascii=False) + "\n")
            sink.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
