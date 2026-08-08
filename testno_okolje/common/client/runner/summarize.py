from __future__ import annotations

from collections import defaultdict

PERCENTILES = (50, 95, 99)


def percentile(values: list[float], pct: float) -> float | None:
    """Metoda najblizjega ranga."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, -(-pct * len(ordered) // 100))
    return ordered[int(rank) - 1]


def _stats(rows: list[dict]) -> dict:
    ok = [row for row in rows if row.get("http_code") == 200]
    times = [row["time_total"] for row in ok if row.get("time_total") is not None]
    return {
        "requests": len(rows),
        "ok": len(ok),
        "errors": len(rows) - len(ok),
        "blocked": sum(1 for row in rows if row.get("blocked")),
        "bytes": sum(row.get("size_download") or 0 for row in rows),
        **{f"p{pct}_ms": _ms(percentile(times, pct)) for pct in PERCENTILES},
    }


def _ms(value: float | None) -> float | None:
    return None if value is None else round(value * 1000, 3)


def summarize(rows: list[dict]) -> dict:
    grouped: dict[str, dict[str, list[dict]]] = {
        "proto": defaultdict(list),
        "category": defaultdict(list),
        "client": defaultdict(list),
        "trust": defaultdict(list),
        "http_version": defaultdict(list),
        "fronting": defaultdict(list),
    }
    for row in rows:
        for key, buckets in grouped.items():
            buckets[str(row.get(key))].append(row)

    return {
        "total": _stats(rows),
        **{
            key: {name: _stats(bucket) for name, bucket in sorted(buckets.items())}
            for key, buckets in grouped.items()
        },
    }
