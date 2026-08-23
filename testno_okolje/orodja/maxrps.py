#!/usr/bin/env python3
"""Najvecja vzdrzna hitrost iz max.json, ki jo zapise iskanje v lib.sh.

Datoteko berejo tako grafi kot lupinski programi meritve, zato je branje na enem
mestu. Modul namenoma ne uvozi matplotliba, ker ga med meritvijo klice lib.sh.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def read(directory: str | Path) -> int | None:
    path = Path(directory) / "max.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8")).get("max_rps")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("uporaba: maxrps.py <imenik z max.json>", file=sys.stderr)
        return 2
    found = read(argv[0])
    print("" if found is None else found)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
