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


INDEX = "/index.html"


def is_document(row: dict) -> bool:
    if "document" in row:
        return bool(row["document"])
    return (row.get("url") or "").endswith(INDEX)


def by_group(rows: list[dict]) -> dict:
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(row.get("group") or "?", []).append(row)

    out = {}
    for group, items in sorted(groups.items()):
        expected = bool(items[0].get("expect_blocked"))
        documents = [r for r in items if is_document(r)]

        def stopped_in(subset: list[dict]) -> int:
            return sum(1 for r in subset if r.get("exitcode") != 0 or r.get("blocked"))

        upstream_fail = sum(1 for r in items if (r.get("http_code") or 0) >= 500)

        stopped_docs = stopped_in(documents)
        matched = stopped_docs if expected else len(documents) - stopped_docs
        out[group] = {
            **stats(items),
            "expect_blocked": expected,
            "pages": len(documents),
            "subresources": len(items) - len(documents),
            "stopped": stopped_in(items),
            "stopped_pages": stopped_docs,
            "upstream_fail": upstream_fail,
            "as_expected_pct": (
                round(matched / len(documents) * 100, 1) if documents else None
            ),
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
