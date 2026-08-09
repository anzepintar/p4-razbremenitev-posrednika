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
    "D": "stikalo P4 brez odlocanja (p4_baseline)",
    "E": "P4 s preusmerjanjem na posrednik (p4_controller_mitm)",
    "F": "P4 z zrcaljenjem na IDS (p4_controller_ids)",
    "G": "resitev: IDS, zanka zaupanja in posrednik (p4_full)",
    "H": "izbirni pregled brez P4, odloca krmilnik (mitm_controller)",
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


def throughput(rows: list[dict]) -> dict:
    got = [r for r in responded(rows)
           if r.get("size_download") and r.get("time_total")]
    if not got:
        return {"prenos_MB": 0.0, "p50_Mbps": None, "p95_Mbps": None, "skupna_Mbps": None}

    rates = [r["size_download"] * 8 / r["time_total"] / 1e6 for r in got]
    total = sum(r["size_download"] for r in got)

    stamped = [r for r in got if r.get("ts") is not None]
    span = None
    if len(stamped) > 1:
        start = min(r["ts"] for r in stamped)
        end = max(r["ts"] + r["time_total"] for r in stamped)
        span = end - start

    return {
        "prenos_MB": round(total / 1e6, 1),
        "p50_Mbps": round(percentile(rates, 50), 2),
        "p95_Mbps": round(percentile(rates, 95), 2),
        "skupna_Mbps": round(total * 8 / span / 1e6, 2) if span else None,
    }


def throughput_table(runs: dict[str, list[dict]]) -> tuple[str, dict]:
    names = list(runs)
    data = {name: {b: throughput(rows) for b, rows in buckets(runs[name]).items()} for name in names}
    keys = sorted({b for name in names for b in data[name]})

    lines = ["Skupina | Zagon | preneseno (MB) | p50 (Mb/s) | p95 (Mb/s) | skupna (Mb/s) | p50 proti prejsnjemu",
             ":--- | :--- | ---: | ---: | ---: | ---: | ---:"]
    for key in keys:
        for index, name in enumerate(names):
            row = data[name].get(key)
            if row is None:
                continue
            previous = data[names[index - 1]].get(key, {}).get("p50_Mbps") if index else None
            lines.append(
                f"{key} | {name} | {row['prenos_MB']} | {row['p50_Mbps']} | "
                f"{row['p95_Mbps']} | {row['skupna_Mbps']} | {_delta(row['p50_Mbps'], previous)}"
            )
    return "\n".join(lines), data


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


def fronting_table(runs: dict[str, list[dict]], alerts: dict[str, list[dict]]) -> tuple[str, dict]:
    """Frontane zahteve: SNI je legitimna domena, streze pa se phishing stran."""
    data = {}
    for name, rows in runs.items():
        fronted = [r for r in rows if r.get("fronting") and r.get("category") == "phishing"]
        flagged = {a.get("sni") for a in alerts.get(name, [])}
        data[name] = {
            "fronted_phishing": len(fronted),
            "blocked": sum(1 for r in fronted if r.get("blocked")),
            "sni_differs": sum(1 for r in fronted if r.get("sni") != r.get("domain")),
            "sni_filter_would_block": sum(1 for r in fronted if r.get("sni") in flagged),
        }

    lines = ["Zagon | frontanih phishing zahtev | SNI != domena | blokiranih po vsebini | ujel bi jih filter po SNI",
             ":--- | ---: | ---: | ---: | ---:"]
    for name, d in data.items():
        lines.append(
            f"{name} | {d['fronted_phishing']} | {d['sni_differs']} | "
            f"{d['blocked']} | {d['sni_filter_would_block']}"
        )
    return "\n".join(lines), data


def source_table(alerts: dict[str, list[dict]], verdicts: dict[str, list[dict]]) -> tuple[str, dict]:
    """Kdo je kaj ujel: IDS po SNI proti posredniku po vsebini."""
    data = {}
    for name in sorted(set(alerts) | set(verdicts)):
        rows = alerts.get(name, [])
        data[name] = {
            "ids_pravilo": sum(1 for a in rows if a.get("source") == "rule"),
            "ids_quic_sni": sum(1 for a in rows if a.get("source") == "quic-sni"),
            "vsebina_blokirano": sum(1 for v in verdicts.get(name, []) if v.get("blocked")),
        }

    lines = ["Zagon | IDS po pravilih | IDS po SNI iz QUIC | blokirano po vsebini",
             ":--- | ---: | ---: | ---:"]
    for name, d in data.items():
        lines.append(
            f"{name} | {d['ids_pravilo']} | {d['ids_quic_sni']} | {d['vsebina_blokirano']}"
        )
    return "\n".join(lines), data


def reaction_table(controller: dict[str, list[dict]]) -> tuple[str, dict]:
    """Odziv krmilnika na zaznavo IDS: znizanje zaupanja in prepis poti."""
    data = {}
    for name, rows in controller.items():
        demotions = [r for r in rows if r.get("source") == "demote"]
        changed = [r for r in demotions if r.get("changed")]
        times = [r["reaction_ms"] for r in changed if r.get("reaction_ms") is not None]
        data[name] = {
            "zaznav": len(demotions),
            "sprememb_poti": len(changed),
            "na_posredniku": sorted({r["src"] for r in changed if r.get("action_after") == "via_mitm"}),
            "reaction_p50_ms": round(percentile(times, 50), 4) if times else None,
            "reaction_p95_ms": round(percentile(times, 95), 4) if times else None,
        }

    lines = ["Zagon | zaznav | sprememb poti | odjemalci na posredniku | p50 (ms) | p95 (ms)",
             ":--- | ---: | ---: | :--- | ---: | ---:"]
    for name, d in data.items():
        lines.append(
            f"{name} | {d['zaznav']} | {d['sprememb_poti']} | "
            f"{', '.join(d['na_posredniku']) or '-'} | "
            f"{d['reaction_p50_ms']} | {d['reaction_p95_ms']}"
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

    verdicts = {name: read_jsonl(out / name / "verdicts.jsonl") for name in runs}
    verdicts = {name: rows for name, rows in verdicts.items() if rows}
    alerts = {name: read_jsonl(out / name / "alerts.jsonl") for name in runs}
    alerts = {name: rows for name, rows in alerts.items() if rows}
    controller = {name: read_jsonl(out / name / "controller.jsonl") for name in runs}
    controller = {name: rows for name, rows in controller.items() if rows}

    sections = [
        ("Zagoni", "Zagon | Pomen\n:--- | :---\n"
         + "\n".join(f"{name} | {RUNS[name]}" for name in runs), None),
    ]
    sections.append(("Latence", *latency_table(runs)))
    sections.append(("Hitrost prenosa", *throughput_table(runs)))
    sections.append(("Zaznava", *detection_table(runs)))
    sections.append(("SNI proti vsebini", *fronting_table(runs, alerts)))
    if alerts or verdicts:
        sections.append(("Vir zaznave", *source_table(alerts, verdicts)))
    if controller:
        sections.append(("Odziv krmilnika", *reaction_table(controller)))

    # Hevristike in cena pregleda se nanasajo na zadnji zagon s pregledom vsebine.
    scanned = verdicts.get("G") or verdicts.get("C") or next(iter(verdicts.values()), [])
    if scanned:
        sections.append(("Hevristika po pragovih", *heuristics_table(scanned)))
        sections.append(("Cena pregleda", *cost_table(scanned)))

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
