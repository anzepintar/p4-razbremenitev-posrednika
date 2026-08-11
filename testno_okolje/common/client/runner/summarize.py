from __future__ import annotations

PERCENTILES = (50, 95, 99)


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, -(-pct * len(ordered) // 100))
    return ordered[int(rank) - 1]


def responded(rows: list[dict]) -> list[dict]:
    return [row for row in rows if row.get("exitcode") == 0 and row.get("time_total") is not None]


def stats(rows: list[dict]) -> dict:
    ok = responded(rows)
    times = [row["time_total"] for row in ok]
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
