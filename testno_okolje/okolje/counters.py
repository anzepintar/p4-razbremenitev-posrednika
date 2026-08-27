"""Imena stevcev stikala, prebrana iz usmerjanje.p4.

Stevci so v programu P4 oznaceni z zaporedno stevilko, nadzorna ravnina in
obdelava rezultatov pa jih naslavljata po imenu. Ce bi se seznama razsla, bi se
v meritvi tiho zamenjala dva stolpca, zato je vir en sam.
"""
from __future__ import annotations

import re
from pathlib import Path

P4 = Path(__file__).resolve().parent / "switch" / "usmerjanje.p4"

PATTERN = re.compile(r"const\s+bit<32>\s+STAT_(\w+)\s*=\s*(\d+)")


def read(path: Path | None = None) -> tuple[str, ...]:
    source = Path(path or P4)
    if not source.is_file():
        raise FileNotFoundError(f"programa P4 ni v {source}, zato imen stevcev ni mogoce prebrati")
    found = PATTERN.findall(source.read_text(encoding="utf-8"))
    if not found:
        raise ValueError(f"{source} nima nobene konstante STAT_")
    return tuple(name.lower() for name, _ in sorted(found, key=lambda item: int(item[1])))


NAMES = read()
