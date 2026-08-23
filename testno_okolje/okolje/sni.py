from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path

KEY_BYTES = 64
LISTS = ("black", "white")
KINDS = ("domain", "ip")
TLS_PORT = 443
DIR = Path(__file__).resolve().parent / "lists"


class SniError(ValueError):
    pass


def path(kind: str, name: str, root: str | Path | None = None) -> Path:
    if kind not in KINDS:
        raise SniError(f"neznana vrsta seznama '{kind}'")
    if name not in LISTS:
        raise SniError(f"neznan seznam '{name}'")
    return Path(root if root is not None else DIR) / f"{kind}_{name}.txt"


def read(file: str | Path) -> list[str]:
    file = Path(file)
    if not file.is_file():
        return []
    items = []
    for line in file.read_text(encoding="utf-8").splitlines():
        text = line.split("#", 1)[0].strip()
        if text:
            items.append(text)
    return sorted(set(items))


def load(kind: str, root: str | Path | None = None) -> dict[str, list[str]]:
    lists = {name: read(path(kind, name, root)) for name in LISTS}
    both = set(lists["black"]) & set(lists["white"])
    if both:
        raise SniError(f"{kind}: {sorted(both)} je hkrati na crnem in belem seznamu")
    if kind == "ip":
        return {name: addresses(items) for name, items in lists.items()}
    return lists


def entry(pattern: str) -> tuple[bytes, bytes, int]:
    name = pattern.encode()
    if not name:
        raise SniError("prazen vzorec")
    if len(name) > KEY_BYTES:
        raise SniError(f"'{pattern}' je daljsi od {KEY_BYTES} bajtov")

    value = name.rjust(KEY_BYTES, b"\x00")
    if pattern.startswith("."):
        mask = (b"\xff" * len(name)).rjust(KEY_BYTES, b"\x00")
        priority = len(name)
    else:
        mask = b"\xff" * KEY_BYTES
        priority = KEY_BYTES + len(name)
    return value, mask, priority


def match(pattern: str) -> str:
    value, mask, _ = entry(pattern)
    return f"0x{value.hex()}&&&0x{mask.hex()}"


def addresses(items: list[str]) -> list[str]:
    prefixes = []
    for item in items:
        text = str(item)
        try:
            ipaddress.ip_network(text, strict=False)
        except ValueError:
            found = sorted({
                info[4][0]
                for info in socket.getaddrinfo(text.split("/")[0], None, socket.AF_INET)
            })
            if not found:
                raise SniError(f"'{text}' se ne razresi v naslov IPv4")
            prefixes += [f"{address}/32" for address in found]
            continue
        prefixes.append(text if "/" in text else f"{text}/32")
    return sorted(set(prefixes))


def _domain_part(pattern: str) -> str:
    return f".+{re.escape(pattern)}" if pattern.startswith(".") else re.escape(pattern)


def _address_part(prefix: str) -> str:
    address, _, bits = prefix.partition("/")
    return re.escape(address if bits in ("", "32") else prefix)


def _pattern(domains: list[str], ips: list[str] | None, suffix: str) -> str:
    parts = [_domain_part(d) for d in sorted(domains)]
    parts += [_address_part(p) for p in sorted(ips or [])]
    if not parts:
        return ""
    return f"^(?:{'|'.join(parts)}){suffix}$"


def ignore_hosts(domains: list[str], ips: list[str] | None = None) -> str:
    return _pattern(domains, ips, f":{TLS_PORT}")


def block_filter(domains: list[str], ips: list[str] | None = None) -> str:
    return _pattern(domains, ips, "")
