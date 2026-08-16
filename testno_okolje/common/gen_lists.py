#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import experiment as exp
import gen_caddyfile
import sni

MARKER_TAG = '<meta name="x-block" content="{marker}">'
HEAD = re.compile(r"<head\b[^>]*>", re.IGNORECASE)

HEADERS = {
    ("domain", "black"): [
        "Domene, ki jih stikalo zavrze ob ClientHello, posrednik pa v prometu QUIC.",
        "Nastalo iz experiment.yml (skupina sni_black) - ne urejaj rocno.",
    ],
    ("domain", "white"): [
        "Domene, ki jih posrednik le tunelira - brez desifriranja in brez potrdila.",
        "Nastalo iz experiment.yml (skupina sni_white) - ne urejaj rocno.",
    ],
    ("ip", "black"): [
        "Naslovi, ki jih stikalo zavrze ze ob paketu SYN.",
        "Nastalo iz experiment.yml (server_ips.ip_black) - ne urejaj rocno.",
    ],
    ("ip", "white"): [
        "Naslovi, ki gredo mimo posrednika naravnost na streznik.",
        "Nastalo iz experiment.yml (server_ips.ip_white) - ne urejaj rocno.",
    ],
}

RULES_HEADER = """# Nastalo iz experiment.yml - ne urejaj rocno, popravi gen_lists.py.
# Utez ime filter; blokira se, ko vsota utezi doseze prag (privzeto 100).
"""


def render(kind: str, name: str, items: list[str]) -> str:
    lines = [f"# {line}" for line in HEADERS[(kind, name)]]
    return "\n".join(lines + [""] + sorted(set(items))) + "\n"


def write_list(kind: str, name: str, items: list[str]) -> int:
    target = sni.path(kind, name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render(kind, name, items), encoding="utf-8")
    return len(set(items))


def write_rules(path: Path) -> None:
    rule = f'100 vsebina ~bs "{exp.CONTENT_MARKER}"\n'
    path.write_text(RULES_HEADER + rule, encoding="utf-8")


def mark_pages(root: Path, domains: list[str]) -> int:
    marker = MARKER_TAG.format(marker=exp.CONTENT_MARKER)
    wanted = set(domains)
    changed = 0
    for directory in root.iterdir():
        page = directory / "index.html"
        if not page.is_file():
            continue
        html = page.read_text(encoding="utf-8", errors="replace")
        has = exp.CONTENT_MARKER in html
        if directory.name in wanted and not has:
            found = HEAD.search(html)
            html = (html[: found.end()] + marker + html[found.end():]) if found else marker + html
            page.write_text(html, encoding="utf-8")
            changed += 1
        elif directory.name not in wanted and has:
            page.write_text(html.replace(marker, ""), encoding="utf-8")
            changed += 1
    return changed


def make_object(root: Path, size_kb: int) -> str:
    target = root / exp.BIG_OBJECT
    if not size_kb:
        for directory in root.iterdir():
            link = directory / exp.BIG_OBJECT
            if link.is_symlink():
                link.unlink()
        target.unlink(missing_ok=True)
        return "big.bin odstranjen"

    size = size_kb * 1024
    if not target.is_file() or target.stat().st_size != size:
        with target.open("wb") as handle:
            chunk = bytes(range(256)) * 4096
            written = 0
            while written < size:
                take = min(len(chunk), size - written)
                handle.write(chunk[:take])
                written += take

    linked = 0
    for directory in root.iterdir():
        if not directory.is_dir():
            continue
        link = directory / exp.BIG_OBJECT
        if link.is_symlink() or link.exists():
            continue
        link.symlink_to(Path("..") / exp.BIG_OBJECT)
        linked += 1
    return f"big.bin {size_kb / 1024:.0f} MB, {linked} novih povezav"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gen_lists")
    parser.add_argument("--config", type=Path, default=exp.CONFIG)
    parser.add_argument("--testset", type=Path, default=HERE / "server" / "testset")
    args = parser.parse_args(argv)

    try:
        experiment = exp.load(args.config)
        data = exp.build(experiment, testset=args.testset)
    except exp.ExperimentError as error:
        print(f"gen_lists.py: {error}", file=sys.stderr)
        return 1

    groups = exp.by_group(data)
    path = exp.write_assignment(data)
    gen_caddyfile.write(args.config, args.testset)

    counts = ", ".join(f"{g} {n}" for g, n in sorted(data["counts"].items()))
    seznami = {
        "domain_black": write_list("domain", "black", groups.get("sni_black", [])),
        "domain_white": write_list("domain", "white", groups.get("sni_white", [])),
        "ip_black": write_list("ip", "black", [experiment.ip_for("ip_black")]),
        "ip_white": write_list("ip", "white", [experiment.ip_for("ip_white")]),
    }
    write_rules(HERE / "lists" / "content_rules.txt")

    root = args.testset / experiment.subset
    changed = mark_pages(root, groups.get("content_block", []))

    print(f"razdelitev: {counts}")
    print("seznami: " + ", ".join(f"{k} {v}" for k, v in seznami.items()))
    print(f"{path.name}, {gen_caddyfile.OUT.name}; oznak spremenjenih {changed}; "
          f"{make_object(root, experiment.object_kb)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
