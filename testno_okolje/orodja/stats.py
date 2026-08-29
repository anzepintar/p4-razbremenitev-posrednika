"""Povprecje in 95-odstotni interval zaupanja cez ponovljene teke meritve.

Modul namenoma ne uvozi matplotliba ne numpyja, ker ga uvaza tudi plot.py, tega pa
med iskanjem maksimuma klice verdict.py.
"""
from __future__ import annotations

from statistics import fmean, stdev

T95 = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
    8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145,
    15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060, 26: 2.056,
    27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
}
NORMAL = 1.96


def t95(df: int) -> float:
    return T95.get(df, NORMAL)


def summary(values: list) -> tuple[float | None, float | None, int]:
    kept = [float(v) for v in values if v is not None]
    if not kept:
        return None, None, 0
    if len(kept) == 1:
        return kept[0], None, 1
    return fmean(kept), t95(len(kept) - 1) * stdev(kept) / len(kept) ** 0.5, len(kept)


def mean(values: list) -> float | None:
    return summary(values)[0]


def spread(values: list) -> float | None:
    return summary(values)[1]
