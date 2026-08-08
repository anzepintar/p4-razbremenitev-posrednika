#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "client"))

from runner.summarize import PERCENTILES, percentile  # noqa: E402

RUNS = {
    "A": "brez posrednika (client_server)",
    "B": "posrednik brez pregleda (mitm_baseline)",
    "C": "posrednik s pregledom vsebine (mitm_baseline + content_block)",
}

THRESHOLDS = (10, 15, 20, 30, 45, 50, 65, 85)


def read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def responded(rows: list[dict]) -> list[dict]:
    """Vse, kar je dobilo odgovor, tudi blokirane 403 - sicer bi C izpadle ravno te."""
    return [r for r in rows if r.get("exitcode") == 0 and r.get("time_total") is not None]


def stats(rows: list[dict]) -> dict:
    times = [r["time_total"] for r in responded(rows)]
    return {
        "requests": len(rows),
        "responded": len(times),
        "blocked": sum(1 for r in rows if r.get("blocked")),
        **{f"p{pct}_ms": _ms(percentile(times, pct)) for pct in PERCENTILES},
    }


def _ms(value: float | None) -> float | None:
    return None if value is None else round(value * 1000, 3)


def _delta(now: float | None, before: float | None) -> str:
    if now is None or before is None:
        return "-"
    if not before:
        return f"{now - before:+.3f}"
    return f"{now - before:+.3f} ({(now - before) / before * 100:+.1f} %)"


def buckets(rows: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {"skupaj": rows}
    for key in ("proto", "category"):
        for row in rows:
            grouped.setdefault(f"{key}={row.get(key)}", []).append(row)
    return grouped


def latency_table(runs: dict[str, list[dict]]) -> tuple[str, dict]:
    names = list(runs)
    data = {name: {b: stats(rows) for b, rows in buckets(runs[name]).items()} for name in names}
    keys = sorted({b for name in names for b in data[name]})

    lines = ["Skupina | Zagon | zahtev | odgovorjenih | blokiranih | p50 (ms) | p95 (ms) | p99 (ms) | p50 proti prejsnjemu",
             ":--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---:"]
    for key in keys:
        for index, name in enumerate(names):
            row = data[name].get(key)
            if row is None:
                continue
            previous = data[names[index - 1]].get(key, {}).get("p50_ms") if index else None
            lines.append(
                f"{key} | {name} | {row['requests']} | {row['responded']} | {row['blocked']} | "
                f"{row['p50_ms']} | {row['p95_ms']} | {row['p99_ms']} | {_delta(row['p50_ms'], previous)}"
            )
    return "\n".join(lines), data


def confusion(rows: list[dict]) -> dict:
    matrix = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for row in rows:
        category = row.get("category")
        if category is None:
            continue
        phish = category == "phishing"
        blocked = bool(row.get("blocked"))
        matrix[("TP" if blocked else "FN") if phish else ("FP" if blocked else "TN")] += 1
    return matrix


def detection_table(runs: dict[str, list[dict]]) -> tuple[str, dict]:
    data = {name: confusion(rows) for name, rows in runs.items()}
    lines = ["Zagon | TP | FP | TN | FN | priklic | preciznost",
             ":--- | ---: | ---: | ---: | ---: | ---: | ---:"]
    for name, m in data.items():
        lines.append(
            f"{name} | {m['TP']} | {m['FP']} | {m['TN']} | {m['FN']} | "
            f"{_ratio(m['TP'], m['TP'] + m['FN'])} | {_ratio(m['TP'], m['TP'] + m['FP'])}"
        )
    return "\n".join(lines), data


def _ratio(part: int, whole: int) -> str:
    return "-" if not whole else f"{part / whole * 100:.1f} %"


def fronting_table(runs: dict[str, list[dict]]) -> tuple[str, dict]:
    """Frontane zahteve: SNI je legitimna domena, streze pa se phishing stran."""
    data = {}
    for name, rows in runs.items():
        fronted = [r for r in rows if r.get("fronting") and r.get("category") == "phishing"]
        data[name] = {
            "fronted_phishing": len(fronted),
            "blocked": sum(1 for r in fronted if r.get("blocked")),
            "sni_differs": sum(1 for r in fronted if r.get("sni") != r.get("domain")),
            "sni_filter_would_block": 0,
        }

    lines = ["Zagon | frontanih phishing zahtev | SNI != domena | blokiranih po vsebini | ujel bi jih filter po SNI",
             ":--- | ---: | ---: | ---: | ---:"]
    for name, d in data.items():
        lines.append(
            f"{name} | {d['fronted_phishing']} | {d['sni_differs']} | "
            f"{d['blocked']} | {d['sni_filter_would_block']}"
        )
    return "\n".join(lines), data


def heuristics_table(verdicts: list[dict], label_rule: str = "testset_label") -> tuple[str, dict]:
    """Kaj bi hevristike ujele same, brez pravila z oznako nabora."""
    scored = [
        {"phish": label_rule in v.get("rules", []), "score": v.get("heuristic_score", 0)}
        for v in verdicts
    ]
    data = {}
    lines = ["Prag | TP | FP | TN | FN | priklic | preciznost",
             ":--- | ---: | ---: | ---: | ---: | ---: | ---:"]
    for threshold in THRESHOLDS:
        m = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        for item in scored:
            hit = item["score"] >= threshold
            m[("TP" if hit else "FN") if item["phish"] else ("FP" if hit else "TN")] += 1
        data[threshold] = m
        lines.append(
            f"{threshold} | {m['TP']} | {m['FP']} | {m['TN']} | {m['FN']} | "
            f"{_ratio(m['TP'], m['TP'] + m['FN'])} | {_ratio(m['TP'], m['TP'] + m['FP'])}"
        )
    return "\n".join(lines), data


def cost_table(verdicts: list[dict]) -> tuple[str, dict]:
    scans = [v["scan_ms"] for v in verdicts if v.get("scan_ms") is not None]
    data = {
        "pregledanih": len(verdicts),
        "blokiranih": sum(1 for v in verdicts if v.get("blocked")),
        "bajtov": sum(v.get("size") or 0 for v in verdicts),
        "scan_avg_ms": round(sum(scans) / len(scans), 4) if scans else None,
        "scan_p95_ms": round(percentile(scans, 95), 4) if scans else None,
    }
    lines = ["Kolicina | Vrednost", ":--- | ---:"]
    lines += [f"{key} | {value}" for key, value in data.items()]
    return "\n".join(lines), data


def build(out: Path) -> tuple[str, dict]:
    runs = {name: read_jsonl(out / name / "metrics.jsonl") for name in RUNS}
    missing = [name for name, rows in runs.items() if not rows]
    runs = {name: rows for name, rows in runs.items() if rows}
    if not runs:
        raise SystemExit(f"v {out} ni nobenega metrics.jsonl - pozeni compare.sh")

    verdicts = read_jsonl(out / "C" / "verdicts.jsonl")

    sections = [
        ("Zagoni", "Zagon | Pomen\n:--- | :---\n"
         + "\n".join(f"{name} | {RUNS[name]}" for name in runs), None),
    ]
    sections.append(("Latence", *latency_table(runs)))
    sections.append(("Zaznava", *detection_table(runs)))
    sections.append(("SNI proti vsebini", *fronting_table(runs)))
    if verdicts:
        sections.append(("Hevristika po pragovih", *heuristics_table(verdicts)))
        sections.append(("Cena pregleda", *cost_table(verdicts)))

    text = "# Primerjava zagonov\n"
    if missing:
        text += f"\n> Manjkajo zagoni: {', '.join(missing)}.\n"
    data: dict = {}
    for title, table, payload in sections:
        text += f"\n## {title}\n\n{table}\n"
        if payload is not None:
            data[title] = payload
    return text, data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=HERE / "out", help="imenik z out/A, out/B, out/C")
    args = parser.parse_args(argv)

    text, data = build(args.out)
    (args.out / "compare.md").write_text(text, encoding="utf-8")
    (args.out / "compare.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(text)
    print(f"-> {args.out / 'compare.md'}, {args.out / 'compare.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
