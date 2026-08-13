#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
from matplotlib.ticker import LogLocator, ScalarFormatter

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "client"))

import sni
from runner.summarize import percentile, responded, stats

CONTENT = "-content"

TOPOLOGIES = ("A0", "B0")

LABELS = {
    "A0": "A0 posrednik",
    "B0": "B0 P4 + posrednik",
}

ERROR_BUDGET = 1.0


def read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def dashes(run: str) -> str:
    return ":" if run.endswith(CONTENT) else "-"


def topology(run: str) -> str:
    return run[: -len(CONTENT)] if run.endswith(CONTENT) else run


def label(run: str) -> str:
    text = LABELS[topology(run)]
    return f"{text} + pregled vsebine" if run.endswith(CONTENT) else text


def tick(run: str) -> str:
    words = label(run).split(" + ")
    return words[0] + "".join(f"\n+ {word}" for word in words[1:])


def order(runs: list[str]) -> list[str]:
    return sorted(runs, key=lambda run: (TOPOLOGIES.index(topology(run)), run))


def discover(base: Path) -> list[str]:
    if not base.is_dir():
        return []
    return order([p.name for p in base.iterdir() if p.is_dir() and topology(p.name) in TOPOLOGIES])


def figure(cols: int = 1, height: float = 4.4, width: float = 5.6):
    fig, axes = plt.subplots(1, cols, figsize=(width * cols, height), squeeze=False)
    return fig, axes[0]


def grid(ax, axis: str = "y") -> None:
    ax.grid(True, axis=axis)
    ax.set_axisbelow(True)


def save(fig, name: str, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    fig.savefig(out / name, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print(f"  {out / name}")


def grouped_bars(runs: list[str], values, series, ylabel: str, name: str, out: Path) -> None:
    fig, axes = figure(width=8.0)
    ax = axes[0]
    grid(ax)

    width = 0.8 / len(series)
    for index, (key, legend) in enumerate(series):
        offset = (index - (len(series) - 1) / 2) * width
        heights = [values[run].get(key) or 0 for run in runs]
        bars = ax.bar([i + offset for i in range(len(runs))], heights, width * 0.9, label=legend)
        ax.bar_label(bars, fmt="%.0f", padding=2, fontsize=8)

    ax.set_xticks(range(len(runs)))
    ax.set_xticklabels([tick(run) for run in runs], fontsize=8)
    ax.set_ylabel(ylabel)
    ax.margins(y=0.18)

    handles, legends = ax.get_legend_handles_labels()
    fig.legend(handles, legends, ncols=len(series), loc="lower center",
               bbox_to_anchor=(0.5, -0.12))
    save(fig, name, out)


def latency_chart(runs: list[str], numbers: dict, out: Path) -> None:
    grouped_bars(runs, numbers, [("p50_ms", "p50"), ("p95_ms", "p95"), ("p99_ms", "p99")],
                 "latenca zahteve (ms)", "latence.png", out)


def throughput_chart(runs: list[str], numbers: dict, out: Path) -> None:
    grouped_bars(runs, numbers, [("p50_Mbps", "p50"), ("p95_Mbps", "p95")],
                 "hitrost zahteve (Mb/s)", "hitrost.png", out)


def ecdf_chart(runs: list[str], metrics: dict, out: Path) -> None:
    fig, axes = figure()
    ax = axes[0]
    grid(ax, axis="both")

    handles = []
    for run in runs:
        times = sorted(row["time_total"] * 1000 for row in responded(metrics[run]))
        if not times:
            continue
        share = [(i + 1) / len(times) for i in range(len(times))]
        line, = ax.plot(times, share, linestyle=dashes(run), linewidth=2, label=label(run))
        handles.append(line)

    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(ScalarFormatter())
    ax.xaxis.set_minor_locator(LogLocator(base=10, subs=(2.0, 5.0)))
    ax.xaxis.set_minor_formatter(ScalarFormatter())
    ax.set_ylim(0, 1.06)
    ax.set_xlabel("latenca zahteve (ms, log)")
    ax.set_ylabel("delež zahtev")
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.16))

    save(fig, "porazdelitev.png", out)


def detection_chart(runs: list[str], metrics: dict, out: Path) -> None:
    switch, blocked, missed, fronted = [], [], [], []
    for run in runs:
        phishing = [p for p in pages(metrics[run]) if p["category"] == "phishing"]
        switch.append(sum(1 for p in phishing if p["switch"]))
        blocked.append(sum(1 for p in phishing if p["blocked"] and not p["switch"]))
        missed.append(sum(1 for p in phishing if not p["blocked"] and not p["switch"]))
        fronted.append(sum(1 for p in phishing if p["fronting"] and not p["switch"]))

    fig, axes = figure(height=0.7 * len(runs) + 1.8, width=8)
    ax = axes[0]
    grid(ax, axis="x")
    ys = range(len(runs))
    left = [0] * len(runs)

    for values, fill, legend in ((switch, None, "zavrnjeno na stikalu (SNI)"),
                                 (blocked, None, "blokirano po vsebini"),
                                 (missed, "lightgrey", "nezaznano")):
        ax.barh(ys, values, left=left, color=fill, label=legend, height=0.6)
        left = [a + b for a, b in zip(left, values)]

    for y, hidden in enumerate(fronted):
        if hidden:
            ax.annotate(f"{hidden} strani", (left[y], y), xytext=(8, 0),
                        textcoords="offset points", va="center", fontsize=8)

    ax.set_yticks(list(ys))
    ax.set_yticklabels([label(run) for run in runs])
    ax.invert_yaxis()
    ax.set_xlabel("phishing nalaganj strani")
    ax.set_xlim(0, max(left + [1]) * 1.22)
    ax.margins(y=0.12)
    ax.legend(ncols=3, loc="upper center", bbox_to_anchor=(0.5, -0.18))
    save(fig, "zaznava.png", out)


def load_chart(runs: list[str], numbers: dict, out: Path) -> None:
    present = [run for run in runs if numbers[run]["to_proxy_pct"] is not None]
    if not present:
        return

    fig, axes = figure(2, height=0.7 * len(present) + 1.6, width=5.0)
    ys = range(len(present))
    columns = (("to_proxy_pct", "paketov do posrednika (%)"),
               ("requests_at_proxy", "zahtev, ki jih posrednik pregleda"))

    for index, (ax, (key, unit)) in enumerate(zip(axes, columns)):
        grid(ax, axis="x")
        values = [numbers[run][key] or 0 for run in present]
        bars = ax.barh(ys, values, 0.6)
        ax.bar_label(bars, fmt="%.0f", padding=3, fontsize=8)
        ax.set_yticks(list(ys))
        ax.set_yticklabels([label(run) for run in present] if index == 0 else [])
        ax.invert_yaxis()
        ax.set_xlabel(unit)
        ax.margins(x=0.18, y=0.12)

    save(fig, "obremenitev.png", out)


def cost_benefit_chart(runs: list[str], numbers: dict, out: Path) -> None:
    points = [(run, numbers[run]["to_proxy_pct"], numbers[run]["caught_pct"])
              for run in runs
              if numbers[run]["to_proxy_pct"] is not None
              and numbers[run]["caught_pct"] is not None]
    if not points:
        return

    fig, axes = figure(width=9, height=5.2)
    ax = axes[0]
    grid(ax, axis="both")

    placed: dict[tuple[int, int], list[str]] = {}
    for run, share, caught in points:
        ax.scatter([share], [caught], s=150, zorder=3)
        placed.setdefault((round(share), round(caught)), []).append(run)

    for index, ((x, y), names) in enumerate(sorted(placed.items())):
        ax.annotate(" · ".join(label(n) for n in names), (x, y),
                    xytext=(0, 12 if index % 2 == 0 else -22), textcoords="offset points",
                    ha="center")

    ax.set_xlim(-6, 112)
    ax.set_ylim(-6, 112)
    ax.set_xlabel("delež paketov odjemalca, ki pripotujejo do posrednika (%)")
    ax.set_ylabel("ujetih phishing strani (%)")
    save(fig, "cena_ucinek.png", out)


def ramp_chart(ramps: dict[str, list[dict]], out: Path) -> None:
    steps = sorted({lv["concurrency"] for levels in ramps.values() for lv in levels})
    fig, axes = figure(2)

    speed, errors = axes
    grid(speed, axis="both")
    handles = []
    for run, levels in ramps.items():
        line, = speed.plot([lv["concurrency"] for lv in levels],
                           [lv["Mbps"] or 0 for lv in levels],
                           linestyle=dashes(run), linewidth=2, marker="o", label=label(run))
        handles.append(line)
    speed.set_xscale("log", base=2)
    speed.set_xticks(steps)
    speed.xaxis.set_major_formatter(ScalarFormatter())
    speed.set_ylabel("hitrost (Mb/s)")

    grid(errors)
    width = 0.8 / len(ramps)
    for index, (run, levels) in enumerate(ramps.items()):
        found = {lv["concurrency"]: lv["errors_pct"] for lv in levels}
        offset = (index - (len(ramps) - 1) / 2) * width
        bars = errors.bar([i + offset for i in range(len(steps))],
                          [found.get(step, 0) for step in steps], width * 0.9)
        errors.bar_label(bars, fmt="%.2g", padding=2, fontsize=8)

    errors.axhline(ERROR_BUDGET, linestyle="--", linewidth=1, color="black")
    errors.set_xticks(range(len(steps)))
    errors.set_xticklabels(steps)
    errors.set_ylabel("delež napak (%)")

    for ax in axes:
        ax.set_xlabel("sočasnih nalaganj strani")
        ax.margins(y=0.18)

    fig.legend(handles=handles, ncols=2, loc="lower center", bbox_to_anchor=(0.5, -0.1))
    save(fig, "ramp.png", out)


BLACK = sni.load("domain")["black"]


def dropped_at_switch(row: dict) -> bool:
    return bool(row.get("exitcode")) and sni.blocks(BLACK, row.get("sni"))


def pages(rows: list[dict]) -> list[dict]:
    grouped: dict[tuple, dict] = {}
    for row in rows:
        page = grouped.setdefault((row["client"], row["ts"]),
                                  {"category": None, "blocked": False, "switch": False,
                                   "fronting": row.get("fronting"), "sni": row.get("sni")})
        if row.get("category"):
            page["category"] = row["category"]
        if row.get("blocked"):
            page["blocked"] = True
        if dropped_at_switch(row):
            page["switch"] = True
            page["category"] = page["category"] or "phishing"
    return list(grouped.values())


def ms(value: float | None) -> float | None:
    return None if value is None else round(value * 1000, 3)


def timespan(rows: list[dict]) -> float | None:
    stamps = [r["ts"] for r in rows if r.get("ts") is not None]
    return max(stamps) - min(stamps) if len(stamps) > 1 else None


def throughput(rows: list[dict]) -> dict:
    got = [r for r in responded(rows) if r.get("size_download") and r.get("time_total")]
    if not got:
        return {"downloaded_MB": 0.0, "p50_Mbps": None, "p95_Mbps": None, "total_Mbps": None}

    rates = [r["size_download"] * 8 / r["time_total"] / 1e6 for r in got]
    total = sum(r["size_download"] for r in got)
    span = timespan(got)
    return {
        "downloaded_MB": round(total / 1e6, 1),
        "p50_Mbps": round(percentile(rates, 50), 2),
        "p95_Mbps": round(percentile(rates, 95), 2),
        "total_Mbps": round(total * 8 / span / 1e6, 2) if span else None,
    }


def detection(rows: list[dict]) -> dict:
    matrix = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for row in rows:
        switch = dropped_at_switch(row)
        if row.get("category") is None and not switch:
            continue
        phish = switch or row.get("category") == "phishing"
        blocked = switch or bool(row.get("blocked"))
        matrix[("TP" if blocked else "FN") if phish else ("FP" if blocked else "TN")] += 1
    matrix["recall_pct"] = ratio(matrix["TP"], matrix["TP"] + matrix["FN"])
    matrix["precision_pct"] = ratio(matrix["TP"], matrix["TP"] + matrix["FP"])
    return matrix


def ratio(part: int, whole: int) -> float | None:
    return None if not whole else round(part / whole * 100, 1)


def proxy_share(ifstats: dict) -> float | None:
    sent = (ifstats.get("client") or {}).get("tx_packets")
    if not sent:
        return None
    if "mitm" not in ifstats:
        return 0.0
    reached = sum((ifstats.get(key) or {}).get("packets", 0)
                  for key in ("intercepted", "passthrough"))
    return round(100 * reached / sent, 1)


def caught_share(rows: list[dict]) -> float | None:
    phishing = [p for p in pages(rows) if p["category"] == "phishing"]
    return ratio(sum(1 for p in phishing if p["blocked"] or p["switch"]), len(phishing))


def level_stats(rows: list[dict], summary: dict) -> dict:
    times = [r["time_total"] for r in rows if r.get("time_total") is not None]
    span = timespan(rows)
    pages_count = len({(r.get("client"), r.get("ts")) for r in rows})
    errors = sum(1 for r in rows if r.get("exitcode") != 0)
    total_bytes = sum(r.get("size_download") or 0 for r in rows)
    return {
        "parallel": summary.get("parallel"),
        "concurrency": summary.get("concurrency"),
        "requests": len(rows),
        "pages": pages_count,
        "duration_s": round(span, 1) if span else None,
        "pages_s": round(pages_count / span, 1) if span else None,
        "Mbps": round(total_bytes * 8 / span / 1e6, 2) if span else None,
        "errors": errors,
        "timeouts": sum(1 for r in rows if r.get("exitcode") == 28),
        "errors_pct": round(errors / len(rows) * 100, 2),
        "p50_ms": ms(percentile(times, 50)),
        "p95_ms": ms(percentile(times, 95)),
        "p99_ms": ms(percentile(times, 99)),
    }


def knee(levels: list[dict]) -> dict | None:
    usable = [lv for lv in levels if lv["errors_pct"] <= ERROR_BUDGET and lv["Mbps"]]
    return max(usable, key=lambda lv: lv["Mbps"]) if usable else None


def load_latency(base: Path) -> tuple[list[str], dict, dict]:
    runs = discover(base)
    metrics = {run: read_jsonl(base / run / "metrics.jsonl") for run in runs}
    runs = [run for run in runs if metrics[run]]

    numbers = {}
    for run in runs:
        rows = metrics[run]
        numbers[run] = {
            **stats(rows),
            **throughput(rows),
            "detection": detection(rows),
            "caught_pct": caught_share(rows),
            "to_proxy_pct": proxy_share(read_json(base / run / "ifstats.json")),
            "requests_at_proxy": len(read_jsonl(base / run / "proxy_flows.jsonl")),
            "switch_sni": read_json(base / run / "switch_sni.json") or None,
        }
    return runs, metrics, numbers


def load_ramp(base: Path) -> dict[str, list[dict]]:
    ramps = {}
    for run in discover(base):
        levels = []
        for level_dir in sorted((base / run).glob("p*"),
                                key=lambda p: int(p.name.lstrip("p") or 0)):
            rows = read_jsonl(level_dir / "metrics.jsonl")
            summary = read_json(level_dir / "summary.json")
            if rows and summary:
                levels.append(level_stats(rows, summary))
        if levels:
            ramps[run] = levels
    return ramps


def check_speed(base: Path, runs: list[str]) -> None:
    speeds = {read_json(base / run / "summary.json").get("speed") for run in runs}
    if len(speeds) > 1:
        print(f"  opozorilo: mešane hitrosti {sorted(map(str, speeds))}, latenc ni mogoče primerjati")


def main() -> int:
    out = HERE / "out"
    graphs = out / "graf"

    runs, metrics, numbers = load_latency(out / "latency")
    ramps = load_ramp(out / "ramp")
    if not runs and not ramps:
        raise SystemExit(f"v {out} ni nobene meritve - poženi measure.sh")

    results: dict = {}
    if runs:
        check_speed(out / "latency", runs)
        print(f"grafi iz {len(runs)} zagonov:")
        latency_chart(runs, numbers, graphs)
        throughput_chart(runs, numbers, graphs)
        ecdf_chart(runs, metrics, graphs)
        detection_chart(runs, metrics, graphs)
        load_chart(runs, numbers, graphs)
        cost_benefit_chart(runs, numbers, graphs)
        results["latency"] = numbers

    if ramps:
        print(f"grafi iz {len(ramps)} ramp:")
        ramp_chart(ramps, graphs)
        results["ramp"] = {run: {"levels": levels, "knee": knee(levels)}
                           for run, levels in ramps.items()}

    (out / "results.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"  {out / 'results.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
