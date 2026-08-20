#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import plot

MIN_RATE_RATIO = float(os.environ.get("MIN_RATE_RATIO", 0.98))
MAX_ERRORS_PCT = float(os.environ.get("MAX_ERRORS_PCT", 0.0))


def judge(directory: Path) -> dict:
    cell = plot.load_cell(directory)
    if cell is None:
        return {"ok": False, "reason": "brez meritev"}

    summary = plot.read_json(directory / "summary.json")
    target = summary.get("rate_target_rps")
    achieved = summary.get("rate_achieved_rps")
    errors = cell.get("errors_pct")

    result = {
        "ok": True,
        "reason": "vzdrzno",
        "target_rps": target,
        "achieved_rps": achieved,
        "errors_pct": errors,
        "total_p95_ms": cell.get("total_p95_ms"),
    }

    if errors is None or errors > MAX_ERRORS_PCT:
        result.update(ok=False, reason=f"napak {errors} % nad {MAX_ERRORS_PCT} %")
    elif target and achieved is not None and achieved < MIN_RATE_RATIO * target:
        result.update(ok=False,
                      reason=f"doseglo {achieved} od {target} zahtev/s "
                             f"(pod {MIN_RATE_RATIO:.0%})")
    return result


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("uporaba: verdict.py <imenik poskusa>", file=sys.stderr)
        return 2

    directory = Path(argv[0])
    result = judge(directory)
    (directory / "verdict.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(result["reason"])
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
