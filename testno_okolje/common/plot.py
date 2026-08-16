#!/usr/bin/env python3
from __future__ import annotations

import json
import statistics
import sys
from collections import namedtuple
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
from matplotlib.colors import TwoSlopeNorm

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "client"))

import experiment as exp
from runner.summarize import is_document, percentile, responded

NODES = ("client", "switch", "mitm", "server")
NODE_LABELS = {
    "client": "odjemalec",
    "switch": "stikalo",
    "mitm": "posrednik",
    "server": "strežnik",
}
MODE_LABELS = {
    "brez": "brez",
    "ip_black": "ip črni seznam",
    "ip_white": "ip beli seznam",
    "sni_black": "domenski črni seznam",
    "sni_white": "domenski beli seznam",
    "content_block": "vsebinski črni seznam",
}
CASE_LABELS = {"brez_quic": "brez QUIC", "z_quic": "s QUIC"}

Layout = namedtuple("Layout", "topos cases modes")
LINK_KEYS = ("rx_packets", "tx_packets", "rx_bytes", "tx_bytes")
SWITCH_KEYS = ("sni_seen", "sni_blocked", "sni_white", "quic",
               "ip_blocked", "ip_white", "denied")

VALID_PCT = 99.0

METRICS = (
    ("goodput_mbps", "propustnost dovoljenega prometa (Mb/s)", True, "ratio"),
    ("total_p50_ms", "latenca dovoljenega prometa p50 (ms)", False, "ratio"),
    ("offload_pct", "razbremenitev posrednika (%)", True, "delta"),
    ("cpu_ms_per_request_mitm", "CPU posrednika na zahtevo (ms)", False, "ratio"),
    ("verdict_p50_s", "čas do razsodbe p50 (s)", False, "ratio"),
)
CENTER = {"ratio": 1.0, "delta": 0.0}
COMPARISON = {"ratio": "večkratnik", "delta": "odstotne točke"}


def read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def figure(rows: int = 1, cols: int = 1, height: float = 3.8, width: float = 5.6):
    fig, axes = plt.subplots(rows, cols, figsize=(width * cols, height * rows),
                             squeeze=False)
    return fig, axes


def grid(ax, axis: str = "y") -> None:
    ax.grid(True, axis=axis)
    ax.set_axisbelow(True)


def save(fig, name: str, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    fig.savefig(out / name, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print(f"  {out / name}")


def ms(value: float | None) -> float | None:
    return None if value is None else round(value * 1000, 2)


def link_delta(before: dict, after: dict) -> dict:
    out: dict = {}
    for node, links in after.items():
        totals = dict.fromkeys(LINK_KEYS, 0)
        for iface, values in links.items():
            was = (before.get(node) or {}).get(iface) or {}
            for key in LINK_KEYS:
                totals[key] += max(0, values.get(key, 0) - was.get(key, 0))
        out[node] = totals
    return out


def counter_delta(before: dict, after: dict) -> dict:
    if not after:
        return {}
    return {key: max(0, after.get(key, 0) - before.get(key, 0)) for key in SWITCH_KEYS}


def packets(values: dict) -> int:
    return values.get("rx_packets", 0) + values.get("tx_packets", 0)


def as_expected_pct(rows: list[dict]) -> float | None:
    documents = [r for r in rows if is_document(r)]
    if not documents:
        return None
    expected = bool(documents[0].get("expect_blocked"))
    stopped = sum(1 for r in documents if r.get("exitcode") != 0 or r.get("blocked"))
    matched = stopped if expected else len(documents) - stopped
    return round(matched / len(documents) * 100, 1)


def flow_groups(assignment: dict) -> dict[str, str]:
    lookup = {domain: info["group"]
              for domain, info in (assignment.get("domains") or {}).items()}
    for group, ip in (assignment.get("server_ips") or {}).items():
        if group != "default":
            lookup.setdefault(ip, group)
    return lookup


def load_cell(directory: Path, groups: dict[str, str] | None = None) -> dict | None:
    background = read_jsonl(directory / "metrics_ozadje.jsonl")
    if not background:
        return None
    summary = read_json(directory / "summary_ozadje.json")
    policy = read_jsonl(directory / "metrics_politika.jsonl")

    seconds = float(summary.get("duration_s") or 0)
    if seconds <= 0:
        return None

    ok = responded(background)
    errors = sum(1 for r in background if r.get("exitcode") != 0)

    links = link_delta(read_json(directory / "links_before.json"),
                       read_json(directory / "links_after.json"))
    client = links.get("client") or {}
    client_pkts = packets(client)
    client_bytes = client.get("rx_bytes", 0) + client.get("tx_bytes", 0)

    nodes = (read_json(directory / "nodes.json") or {}).get("summary") or {}
    requests = len(background) + len(policy)

    def cpu_ms(node: str, divisor: int) -> float | None:
        values = nodes.get(node)
        if not values or not divisor:
            return None
        return round((values.get("cpu_pct_avg") or 0) / 100 * seconds * 1000 / divisor, 6)

    verdicts = [r["time_total"] for r in policy
                if is_document(r) and r.get("time_total") is not None]

    flow_log = directory / "proxy_flows.jsonl"
    flows = read_jsonl(flow_log)
    offload_pct = (round(100 * (1 - len(flows) / requests), 1)
                   if flow_log.is_file() and requests else None)

    mode = policy[0].get("group") if policy else None
    policy_flows = sum(
        1 for f in flows
        if (groups or {}).get(str(f.get("host") or "").split(":")[0]) == mode
    ) if (mode and groups) else None

    cell = {
        "goodput_mbps": round(sum(r.get("size_download") or 0 for r in background)
                              * 8 / seconds / 1e6, 2),
        "handshake_p50_ms": ms(percentile([r["time_appconnect"] for r in ok
                                           if r.get("time_appconnect") is not None], 50)),
        "total_p50_ms": ms(percentile([r["time_total"] for r in ok], 50)),
        "total_p95_ms": ms(percentile([r["time_total"] for r in ok], 95)),
        "offload_pct": offload_pct,
        "verdict_p50_s": (round(percentile(verdicts, 50), 3) if verdicts else None),
        "policy_ok_pct": as_expected_pct(policy) if policy else None,
        "background_requests": len(background),
        "policy_requests": len(policy),
        "errors_pct": round(errors / len(background) * 100, 2) if background else None,
        "wire_mbps": round(client.get("rx_bytes", 0) * 8 / seconds / 1e6, 2),
        "packets_s": round(client_pkts / seconds, 1) if client_pkts else None,
        "bytes_per_packet": (round(client_bytes / client_pkts, 1)
                             if client_pkts else None),
        "proxy_sessions": len(flows),
        "proxy_sessions_per_policy_request": (
            round(policy_flows / len(policy), 3) if policy_flows is not None else None),
        "duration_s": seconds,
        "switch": counter_delta(read_json(directory / "switch_before.json"),
                                read_json(directory / "switch_after.json")),
    }
    for node in NODES:
        cell[f"cpu_ms_per_request_{node}"] = cpu_ms(node, requests)
        cell[f"cpu_ms_per_packet_{node}"] = cpu_ms(node, packets(links.get(node) or {}))
        cell[f"mem_mb_{node}"] = (nodes.get(node) or {}).get("mem_mb_avg")
    return cell


def collect(base: Path, groups: dict[str, str]) -> dict:
    runs: dict = {}
    for directory in sorted(base.glob("r*/*/*/*")) if base.is_dir() else []:
        cell = load_cell(directory, groups) if directory.is_dir() else None
        if cell is not None:
            topo, case, mode = directory.parts[-3:]
            runs.setdefault((topo, case, mode), []).append(cell)
    return runs


def collect_ramp(base: Path, groups: dict[str, str]) -> dict:
    runs: dict = {}
    for directory in sorted(base.glob("*/*/w*")) if base.is_dir() else []:
        cell = load_cell(directory, groups)
        if cell is not None:
            topo, case, step = directory.parts[-3:]
            runs[(topo, case, int(step[1:]))] = cell
    return runs


def agg(values: list) -> dict | None:
    numbers = [v for v in values if isinstance(v, (int, float))]
    if not numbers:
        return None
    return {
        "med": round(statistics.median(numbers), 4),
        "min": round(min(numbers), 4),
        "max": round(max(numbers), 4),
        "n": len(numbers),
    }


def aggregate(runs: dict) -> dict:
    out: dict = {}
    for key, cells in runs.items():
        merged: dict = {}
        for field in cells[0]:
            if field == "switch":
                merged["switch"] = {
                    name: agg([(c.get("switch") or {}).get(name) for c in cells])
                    for name in SWITCH_KEYS
                }
                continue
            merged[field] = agg([c.get(field) for c in cells])
        out[key] = merged
    return out


def med(cell: dict | None, key: str) -> float | None:
    entry = (cell or {}).get(key)
    return entry["med"] if entry else None


def bars(ax, data: dict, case: str, key: str, layout) -> None:
    grid(ax)
    width = 0.8 / len(layout.topos)
    for index, topo in enumerate(layout.topos):
        offset = (index - (len(layout.topos) - 1) / 2) * width
        heights, lower, upper, hatches, labels = [], [], [], [], []
        for mode in layout.modes:
            cell = data.get((topo, case, mode))
            entry = (cell or {}).get(key)
            value = entry["med"] if entry else float("nan")
            heights.append(value)
            lower.append(value - entry["min"] if entry else 0)
            upper.append(entry["max"] - value if entry else 0)
            labels.append(f"{value:.3g}" if entry else "")
            ok = med(cell, "policy_ok_pct")
            hatches.append(bool(entry) and ok is not None and ok < VALID_PCT)
        drawn = ax.bar([i + offset for i in range(len(layout.modes))], heights,
                       width * 0.9, yerr=[lower, upper], capsize=2, label=topo)
        for rect, hatched in zip(drawn, hatches):
            if hatched:
                rect.set_hatch("//")
        ax.bar_label(drawn, labels=labels, padding=2, fontsize=7)
    ax.set_xticks(range(len(layout.modes)))
    ax.set_xticklabels([MODE_LABELS.get(m, m) for m in layout.modes],
                       fontsize=8, rotation=25, ha="right")
    ax.margins(y=0.22)


def metric_chart(data: dict, rows: list[tuple[str, str]], name: str, out: Path,
                 layout) -> None:
    fig, axes = figure(len(rows), len(layout.cases),
                       width=max(5.0, 1.15 * len(layout.modes)))
    for row, (key, ylabel) in enumerate(rows):
        for col, case in enumerate(layout.cases):
            ax = axes[row][col]
            bars(ax, data, case, key, layout)
            ax.set_ylabel(ylabel)
            if row == 0:
                ax.set_title(CASE_LABELS.get(case, case))
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, ncols=len(layout.topos), loc="lower center",
               bbox_to_anchor=(0.5, -0.06 / len(rows)))
    fig.tight_layout()
    save(fig, name, out)


def advantage(data: dict, key: str, case: str, mode: str, higher_better: bool,
              kind: str, topos: list[str]) -> float | None:
    if len(topos) != 2:
        return None
    cells = [data.get((topo, case, mode)) for topo in topos]
    for cell in cells:
        ok = med(cell, "policy_ok_pct")
        if ok is not None and ok < VALID_PCT:
            return None
    a, b = (med(cell, key) for cell in cells)
    if a is None or b is None:
        return None
    if kind == "delta":
        return round(b - a if higher_better else a - b, 1)
    top, bottom = (b, a) if higher_better else (a, b)
    return round(top / bottom, 2) if bottom else None


def overview_heatmap(data: dict, out: Path, layout) -> None:
    columns = [(case, mode) for case in layout.cases for mode in layout.modes]
    values = [
        [advantage(data, key, case, mode, higher, kind, layout.topos)
         for case, mode in columns]
        for key, _, higher, kind in METRICS
    ]
    if not any(v is not None for row in values for v in row):
        return

    cmap = matplotlib.colormaps["coolwarm"]
    pixels = []
    for line, (_, _, _, kind) in zip(values, METRICS):
        center = CENTER[kind]
        seen = [v for v in line if v is not None]
        reach = max([abs(v - center) for v in seen] or [1.0]) or 1.0
        norm = TwoSlopeNorm(vcenter=center, vmin=center - reach, vmax=center + reach)
        pixels.append([(1, 1, 1, 0) if v is None else cmap(norm(v)) for v in line])

    fig, axes = figure(1, 1, height=0.62 * len(METRICS) + 2.0,
                       width=1.15 * len(columns) + 3)
    ax = axes[0][0]
    ax.imshow(pixels, aspect="auto")

    for row, line in enumerate(values):
        for col, value in enumerate(line):
            ax.text(col, row, "-" if value is None else f"{value:g}",
                    ha="center", va="center", fontsize=8)

    ax.set_xticks(range(len(columns)))
    ax.set_xticklabels([f"{MODE_LABELS.get(mode, mode)}\n{CASE_LABELS.get(case, case)}"
                        for case, mode in columns], fontsize=7)
    ax.set_yticks(range(len(METRICS)))
    ax.set_yticklabels(
        [f"{label.rsplit(' (', 1)[0]}\n({COMPARISON[kind]})"
         for _, label, _, kind in METRICS], fontsize=8)
    ax.set_title(f"prednost {layout.topos[-1]} pred {layout.topos[0]}; "
                 "nad sredino je boljše, prazno pomeni neveljavno politiko")
    fig.tight_layout()
    save(fig, "pregled.png", out)


def calibration_chart(ramp: dict, out: Path, cases: list[str], topos: list[str]) -> None:
    steps = sorted({w for _, _, w in ramp})
    if not steps:
        return
    fig, axes = figure(1, 2, width=6.0)
    for ax, (key, ylabel) in zip(axes[0], (("goodput_mbps", "propustnost (Mb/s)"),
                                           ("errors_pct", "delež napak (%)"))):
        grid(ax)
        for topo in topos:
            for case in cases:
                heights = [(ramp.get((topo, case, w)) or {}).get(key) for w in steps]
                ax.plot(steps, heights, marker="o",
                        label=f"{topo} {CASE_LABELS.get(case, case)}")
        ax.set_xscale("log", base=2)
        ax.set_xticks(steps)
        ax.set_xticklabels(steps)
        ax.set_xlabel("sočasnih zahtev")
        ax.set_ylabel(ylabel)
    handles, labels = axes[0][0].get_legend_handles_labels()
    fig.legend(handles, labels, ncols=2, loc="lower center", bbox_to_anchor=(0.5, -0.14))
    fig.tight_layout()
    save(fig, "kalibracija.png", out)


def results_table(data: dict, layout) -> str:
    header = ["postavitev", "protokol", "način"] + \
        [label for _, label, _, _ in METRICS] + ["pravilnost (%)", "seje/zahtevo"]
    lines = ["| " + " | ".join(header) + " |",
             "| " + " | ".join([":---"] * len(header)) + " |"]
    for topo in layout.topos:
        for case in layout.cases:
            for mode in layout.modes:
                cell = data.get((topo, case, mode))
                if cell is None:
                    continue
                row = [topo, CASE_LABELS.get(case, case), MODE_LABELS.get(mode, mode)]
                for key, _, _, _ in METRICS:
                    value = med(cell, key)
                    row.append("-" if value is None else f"{value:g}")
                for key in ("policy_ok_pct", "proxy_sessions_per_policy_request"):
                    value = med(cell, key)
                    row.append("-" if value is None else f"{value:g}")
                lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"


def main() -> int:
    out = HERE / "out"
    graphs = out / "graf"
    settings = exp.load()

    groups = flow_groups(exp.read_assignment())
    runs = collect(out / "matrix", groups)
    ramp = collect_ramp(out / "calibrate", groups)
    if not runs and not ramp:
        raise SystemExit(f"v {out} ni nobene meritve - pozeni measure.sh")

    results: dict = {}

    if runs:
        layout = Layout(
            topos=[t for t in settings.topologies if any(k[0] == t for k in runs)],
            cases=[c for c in sorted(settings.cases) if any(k[1] == c for k in runs)],
            modes=[m for m in settings.modes if any(k[2] == m for k in runs)],
        )
        data = aggregate(runs)
        print(f"matrika: {len(runs)} celic, do "
              f"{max(len(v) for v in runs.values())} ponovitev")

        for name, rows in (
            ("m1_propustnost.png", [("goodput_mbps", "propustnost dovoljenega prometa (Mb/s)")]),
            ("m2_latenca.png", [("total_p50_ms", "latenca p50 (ms)"),
                                ("total_p95_ms", "latenca p95 (ms)")]),
            ("m3_razbremenitev.png", [("offload_pct", "razbremenitev posrednika (%)")]),
            ("m4_cpu.png", [(f"cpu_ms_per_request_{n}",
                             f"CPU {NODE_LABELS[n]} (ms/zahtevo)")
                            for n in ("mitm", "switch")]),
            ("m5_razsodba.png", [("verdict_p50_s", "čas do razsodbe p50 (s)")]),
        ):
            metric_chart(data, rows, name, graphs, layout)
        overview_heatmap(data, graphs, layout)

        results["matrix"] = {f"{t}/{c}/{m}": v for (t, c, m), v in data.items()}
        (out / "results.md").write_text(results_table(data, layout), encoding="utf-8")
        print(f"  {out / 'results.md'}")

    if ramp:
        print(f"kalibracija: {len(ramp)} tekov")
        calibration_chart(ramp, graphs, sorted({c for _, c, _ in ramp}),
                          [t for t in settings.topologies if any(k[0] == t for k in ramp)])
        results["calibrate"] = {f"{t}/{c}/w{w}": v for (t, c, w), v in ramp.items()}

    (out / "results.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8")
    print(f"  {out / 'results.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
