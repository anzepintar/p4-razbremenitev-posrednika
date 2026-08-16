#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import re
import shutil
import sys
from itertools import zip_longest
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent

LABELS = {"ben": "legit", "mal": "phishing"}

DATASET = HERE.parent.parent / "testni_podatki" / "LNU-Phish-raw_no-screenshot"

LEGIT_SOURCES = [
    "legit/alexa_top/alexa_top.json",
    "legit/alexa_medium/alexa_medium.json",
    "legit/alexa_bottom/alexa_bottom.json",
]
PHISH_SOURCES = [
    "phishing/openPhish/data/openPhish.json",
    "phishing/phishTank/data/phishTank.json",
]

SETS = {"testni": (950, 50)}

CHUNK = 1 << 20

MARKER = '<meta name="x-testset-label" content="{category}">'
HEAD = re.compile(r"<head\b[^>]*>", re.IGNORECASE)

ASSET = "_asset.bin"
ASSET_SIZE = 24 * 1024


def iter_records(path: Path):
    decoder = json.JSONDecoder()
    with path.open(encoding="utf-8", errors="replace") as handle:
        buffer = handle.read(CHUNK)
        index = buffer.find("{")
        while True:
            if index < 0 or index >= len(buffer):
                more = handle.read(CHUNK)
                if not more:
                    return
                buffer += more
                continue
            try:
                record, end = decoder.raw_decode(buffer, index)
            except json.JSONDecodeError:
                more = handle.read(CHUNK)
                if not more:
                    return
                buffer += more
                continue

            yield record

            buffer = buffer[end:]
            index = buffer.find("{")


def domain_of(url: str) -> str:
    candidate = url.strip()
    if "//" not in candidate:
        candidate = "//" + candidate
    return urlsplit(candidate).hostname.strip(".").lower()


def take_from(path: Path, quota: int, seen: set[str]) -> list[dict]:
    picked: list[dict] = []
    for record in iter_records(path):
        if len(picked) >= quota:
            break
        if record["status_code"] != 200:
            continue
        domain = domain_of(record["URL"])
        if not domain.rsplit(".", 1)[-1].isalpha():
            continue
        if domain in seen:
            continue
        seen.add(domain)
        picked.append(
            {
                "domain": domain,
                "label": record["label"],
                "websource": record["websource"],
                "rank": record["rank"],
                "url": record["URL"],
                "html": record["HTML"],
            }
        )
    return picked


def interleave(groups: list[list[dict]]) -> list[dict]:
    return [item for row in zip_longest(*groups) for item in row if item is not None]


def collect(sources: list[str], wanted: int, seen: set[str], dataset: Path) -> list[dict]:
    available = [dataset / relative for relative in sources]

    groups: list[list[dict]] = []
    quota, remainder = divmod(wanted, len(available))
    for index, path in enumerate(available):
        share = quota + (1 if index < remainder else 0)
        got = take_from(path, share, seen)
        print(f"  {path.parent.name}/{path.name}: {len(got)}")
        groups.append(got)

    picked = interleave(groups)
    for index, path in enumerate(available):
        if len(picked) >= wanted:
            break
        extra = take_from(path, wanted - len(picked), seen)
        if extra:
            print(f"  {path.parent.name}/{path.name}: +{len(extra)} (dopolnitev)")
            picked += extra
    return picked


def mark(html: str, label: str) -> str:
    marker = MARKER.format(category=LABELS[label])
    found = HEAD.search(html)
    if found:
        return html[: found.end()] + marker + html[found.end() :]
    return marker + html


def write_set(name: str, sites: list[dict], out: Path) -> None:
    target = out / name
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)

    (target / ASSET).write_bytes(random.Random(0).randbytes(ASSET_SIZE))

    manifest = []
    for site in sites:
        directory = target / site["domain"]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "index.html").write_text(
            mark(site["html"], site["label"]), encoding="utf-8"
        )
        (directory / ASSET).symlink_to(Path("..") / ASSET)
        manifest.append({k: v for k, v in site.items() if k != "html"})

    (target / "sites.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    benign = sum(1 for s in manifest if s["label"] == "ben")
    print(f"{name}: {len(manifest)} strani ({benign} legit, {len(manifest) - benign} phishing)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=DATASET, help="izvorni LNU-Phish")
    parser.add_argument("--out", type=Path, default=HERE / "server" / "testset")
    args = parser.parse_args(argv)

    if not args.dataset.is_dir():
        print(f"nabora podatkov ni v {args.dataset}", file=sys.stderr)
        return 1

    seen: set[str] = set()
    total_legit = sum(counts[0] for counts in SETS.values())
    total_phish = sum(counts[1] for counts in SETS.values())

    legit = collect(LEGIT_SOURCES, total_legit, seen, args.dataset)
    phish = collect(PHISH_SOURCES, total_phish, seen, args.dataset)

    print()
    legit_pos = phish_pos = 0
    for name, (want_legit, want_phish) in SETS.items():
        chosen = (
            legit[legit_pos : legit_pos + want_legit] + phish[phish_pos : phish_pos + want_phish]
        )
        legit_pos += want_legit
        phish_pos += want_phish
        write_set(name, chosen, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
