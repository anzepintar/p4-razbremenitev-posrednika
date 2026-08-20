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


def stopped(rows: list[dict]) -> int:
    return sum(1 for row in rows if row.get("exitcode") != 0 or row.get("blocked"))


def as_expected_pct(rows: list[dict]) -> float | None:
    if not rows:
        return None
    expected = bool(rows[0].get("expect_blocked"))
    halted = stopped(rows)
    matched = halted if expected else len(rows) - halted
    return round(matched / len(rows) * 100, 1)


def by_group(rows: list[dict]) -> dict:
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(row.get("group") or "?", []).append(row)

    out = {}
    for group, items in sorted(groups.items()):
        out[group] = {
            **stats(items),
            "expect_blocked": bool(items[0].get("expect_blocked")),
            "stopped": stopped(items),
            "upstream_fail": sum(1 for r in items if (r.get("http_code") or 0) >= 500),
            "as_expected_pct": as_expected_pct(items),
        }
    return out


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
