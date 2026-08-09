#!/usr/bin/env python3
"""Iz out/<zagon>/ naredi grafe v out/graf/"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402

HERE = Path(__file__).resolve().parent

RUNS = {
    "A": "A brez posrednika",
    "B": "B posrednik",
    "C": "C posrednik + vsebina",
    "H": "H izbirni pregled",
    "D": "D stikalo P4",
    "E": "E P4 + posrednik",
    "F": "F P4 + IDS",
    "G": "G resitev",
}
def caption(names: list[str]) -> str:
    return " · ".join(RUNS[n] for n in names)

PANELS = [("Brez stikala", ["A", "B", "C", "H"]), ("Prek stikala P4", ["D", "E", "F", "G"])]

COLOR = {
    "A": "#2a78d6", "B": "#eb6834", "C": "#1baf7a", "H": "#eda100",
    "D": "#e87ba4", "E": "#008300", "F": "#4a3aa7", "G": "#e34948",
}
STYLE = {"A": "-", "B": "--", "C": "-.", "H": ":", "D": "-", "E": "--", "F": "-.", "G": ":"}

SLOT = ("#2a78d6", "#eb6834", "#1baf7a")
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_SOFT = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
NEUTRAL = "#d5d4cd"


def read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def style_axes(ax, *, grid_axis: str = "y") -> None:
    ax.set_facecolor(SURFACE)
    ax.grid(True, axis=grid_axis, color=GRID, linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(AXIS)
        ax.spines[side].set_linewidth(1.0)
    ax.tick_params(colors=MUTED, labelsize=9, length=0)


def figure(rows: int = 1, cols: int = 1, size=(10, 4.5)):
    fig, axes = plt.subplots(rows, cols, figsize=size, facecolor=SURFACE)
    return fig, axes


SUBTITLE = ""


def save(fig, path: Path) -> None:
    if SUBTITLE:
        fig.text(0.98, 0.965, SUBTITLE, fontsize=9, color=MUTED, ha="right", va="top")
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160, facecolor=SURFACE, bbox_inches="tight")
    plt.close(fig)
    print(f"  {path}")


def describe(metrics: dict[str, list[dict]], summaries: dict[str, dict]) -> str:
    """Slika mora povedati, iz cesa je; ob mesanih hitrostih latenc ni dovoljeno primerjati."""
    counts = {len(rows) for rows in metrics.values()}
    speeds = {summary.get("speed") for summary in summaries.values()}
    rows = f"{counts.pop()} zahtev na zagon" if len(counts) == 1 else "razlicno stevilo zahtev"

    if len(speeds) == 1:
        speed = speeds.pop()
        return f"{rows}, isti seed, hitrost {speed if speed is not None else 1}"
    print(f"  opozorilo: zagoni imajo razlicne hitrosti {sorted(map(str, speeds))}")
    return f"{rows} — POZOR: mesane hitrosti {sorted(map(str, speeds))}, latenc ni mogoce primerjati"


def latency_chart(summaries: dict[str, dict], out: Path) -> None:
    fig, axes = figure(1, 2, (11, 4.4))
    stats = [("p50_ms", "p50"), ("p95_ms", "p95"), ("p99_ms", "p99")]

    for ax, (title, names) in zip(axes, PANELS):
        present = [n for n in names if n in summaries]
        style_axes(ax)
        if not present:
            ax.set_visible(False)
            continue

        width = 0.26
        for index, (key, label) in enumerate(stats):
            xs = [i + (index - 1) * width for i in range(len(present))]
            values = [summaries[n]["total"].get(key) or 0 for n in present]
            bars = ax.bar(xs, values, width * 0.92, label=label, color=SLOT[index],
                          zorder=2, linewidth=0)
            ax.bar_label(bars, fmt="%.0f", padding=2, fontsize=8, color=INK_SOFT)

        ax.set_xticks(range(len(present)))
        ax.set_xticklabels(present, fontsize=11, color=INK)
        ax.set_xlabel(caption(present), fontsize=8, color=MUTED)
        ax.set_title(title, fontsize=11, color=INK, loc="left", pad=10)
        ax.set_ylabel("latenca zahteve (ms)", fontsize=9, color=INK_SOFT)
        ax.margins(y=0.16)

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, frameon=False, fontsize=9, labelcolor=INK_SOFT,
               ncols=3, loc="lower center", bbox_to_anchor=(0.5, -0.06))
    fig.suptitle("Latenca po postavitvah", fontsize=13, color=INK, x=0.02, ha="left")
    save(fig, out / "latence.png")


def ecdf_chart(metrics: dict[str, list[dict]], out: Path) -> None:
    fig, axes = figure(1, 2, (11, 4.4))

    for ax, (title, names) in zip(axes, PANELS):
        present = [n for n in names if metrics.get(n)]
        style_axes(ax, grid_axis="both")
        if not present:
            ax.set_visible(False)
            continue

        for name in present:
            times = sorted(
                row["time_total"] * 1000
                for row in metrics[name]
                if row.get("exitcode") == 0 and row.get("time_total") is not None
            )
            if not times:
                continue
            share = [(i + 1) / len(times) for i in range(len(times))]
            ax.plot(times, share, color=COLOR[name], linestyle=STYLE[name],
                    linewidth=2, zorder=2)
            ax.annotate(name, (times[-1], 1.0), xytext=(4, -2), textcoords="offset points",
                        fontsize=9, color=COLOR[name], fontweight="bold")

        ax.set_xscale("log")
        ax.set_ylim(0, 1.06)
        ax.set_title(title, fontsize=11, color=INK, loc="left", pad=10)
        ax.set_xlabel("latenca zahteve (ms, log)", fontsize=9, color=INK_SOFT)
        ax.set_ylabel("delez zahtev", fontsize=9, color=INK_SOFT)
        ax.legend(handles=[Line2D([], [], color=COLOR[n], linestyle=STYLE[n], linewidth=2,
                                  label=RUNS[n]) for n in present],
                  frameon=False, fontsize=9, labelcolor=INK_SOFT, ncols=2,
                  loc="upper center", bbox_to_anchor=(0.5, -0.18))

    fig.suptitle("Porazdelitev latenc", fontsize=13, color=INK, x=0.02, ha="left")
    save(fig, out / "porazdelitev.png")


def pages(rows: list[dict]) -> list[dict]:
    """Blokira se stran, ne podvir, zato se zaznava meri na nalaganje strani."""
    grouped: dict[tuple, dict] = {}
    for row in rows:
        page = grouped.setdefault((row["client"], row["ts"]),
                                  {"category": None, "blocked": False,
                                   "fronting": row.get("fronting"), "sni": row.get("sni")})
        if row.get("category"):
            page["category"] = row["category"]
        if row.get("blocked"):
            page["blocked"] = True
    return list(grouped.values())


def coverage(rows: list[dict]) -> tuple[int, int]:
    phishing = [p for p in pages(rows) if p["category"] == "phishing"]
    return sum(1 for p in phishing if p["blocked"]), len(phishing)


def detection_chart(metrics: dict[str, list[dict]], alerts: dict[str, list[dict]],
                    out: Path) -> None:
    order = [n for n in ("A", "B", "C", "H", "D", "E", "F", "G") if metrics.get(n)]
    blocked, by_ids, missed, fronted = [], [], [], []

    for name in order:
        phishing = [p for p in pages(metrics[name]) if p["category"] == "phishing"]
        flagged = {a.get("sni") for a in alerts.get(name, [])}
        blocked.append(sum(1 for p in phishing if p["blocked"]))
        by_ids.append(sum(1 for p in phishing if not p["blocked"] and p["sni"] in flagged))
        missed.append(sum(1 for p in phishing
                          if not p["blocked"] and p["sni"] not in flagged))
        fronted.append(sum(1 for p in phishing if p["fronting"]))

    fig, ax = figure(size=(10, 4.6))
    style_axes(ax, grid_axis="x")
    ys = range(len(order))
    left = [0] * len(order)

    for values, color, label in (
        (blocked, SLOT[0], "blokirano po vsebini"),
        (by_ids, SLOT[1], "IDS ujel po SNI"),
        (missed, NEUTRAL, "nezaznano"),
    ):
        ax.barh(ys, values, left=left, color=color, label=label, height=0.6,
                edgecolor=SURFACE, linewidth=1.5, zorder=2)
        left = [a + b for a, b in zip(left, values)]

    for y, (caught, hidden) in enumerate(zip(blocked, fronted)):
        if hidden:
            ax.annotate(f"{hidden} frontanih", (left[y], y), xytext=(8, 0),
                        textcoords="offset points", va="center", fontsize=8, color=INK_SOFT)

    ax.set_yticks(list(ys))
    ax.set_yticklabels([RUNS[n] for n in order], fontsize=9, color=INK_SOFT)
    ax.invert_yaxis()
    ax.set_xlabel("phishing nalaganj strani", fontsize=9, color=INK_SOFT)
    ax.set_xlim(0, max(left + [1]) * 1.22)
    ax.legend(frameon=False, fontsize=9, labelcolor=INK_SOFT, ncols=3,
              loc="upper center", bbox_to_anchor=(0.5, -0.14))
    total = max(left + [0])
    fig.suptitle(f"Kaj katera postavitev ujame ({total} phishing strani na zagon)",
                 fontsize=13, color=INK, x=0.02, ha="left")
    save(fig, out / "zaznava.png")


def load_share(stats: dict) -> float | None:
    """Delez paketov odjemalca, ki sploh pripotujejo do posrednika."""
    sent = (stats.get("client") or {}).get("tx_packets")
    if not sent:
        return None
    if "mitm" not in stats:
        return 0.0
    reached = sum((stats.get(key) or {}).get("packets", 0)
                  for key in ("intercepted", "passthrough"))
    return 100 * reached / sent


def cost_benefit_chart(metrics: dict[str, list[dict]], ifstats: dict[str, dict],
                       out: Path) -> None:
    fig, ax = figure(size=(9, 5.2))
    style_axes(ax, grid_axis="both")

    groups: dict[tuple[int, int], list[str]] = {}
    for name, rows in metrics.items():
        share = load_share(ifstats.get(name, {}))
        caught, total = coverage(rows)
        if share is None or not total:
            continue
        y = 100 * caught / total
        ax.scatter([share], [y], s=150, color=COLOR[name], zorder=3, linewidths=0)
        groups.setdefault((round(share), round(y)), []).append(name)

    for (x, y), names in groups.items():
        label = RUNS[names[0]] if len(names) == 1 else " · ".join(sorted(names))
        right = x > 60
        ax.annotate(label, (x, y), xytext=(-10 if right else 10, 8),
                    textcoords="offset points", fontsize=9, color=INK,
                    ha="right" if right else "left")

    ax.set_xlim(-6, 112)
    ax.set_ylim(-6, 112)
    ax.set_xlabel("delez paketov odjemalca, ki pripotujejo do posrednika (%)",
                  fontsize=9, color=INK_SOFT)
    ax.set_ylabel("ujetih phishing strani (%)", fontsize=9, color=INK_SOFT)
    fig.suptitle("Cena in ucinek: manj prometa na posredniku ob enaki zaznavi",
                 fontsize=13, color=INK, x=0.02, ha="left")
    save(fig, out / "cena_ucinek.png")


def load_chart(ifstats: dict[str, dict], flows: dict[str, list[dict]], out: Path) -> None:
    order = [n for n in ("A", "B", "C", "H", "D", "E", "F", "G") if n in ifstats]
    shares = [load_share(ifstats[n]) or 0 for n in order]
    sessions = [len(flows.get(n, [])) for n in order]

    fig, axes = figure(1, 2, (11, 4.4))
    for ax, values, title, unit in (
        (axes[0], shares, "Omrezna cena", "paketov do posrednika (%)"),
        (axes[1], sessions, "Procesorska cena", "sej, ki jih posrednik razstavi"),
    ):
        style_axes(ax)
        bars = ax.bar(range(len(order)), values, 0.6,
                      color=[COLOR[n] for n in order], zorder=2, linewidth=0)
        ax.bar_label(bars, fmt="%.0f", padding=2, fontsize=8, color=INK_SOFT)
        ax.set_xticks(range(len(order)))
        ax.set_xticklabels(order, fontsize=11, color=INK)
        ax.set_title(title, fontsize=11, color=INK, loc="left", pad=10)
        ax.set_ylabel(unit, fontsize=9, color=INK_SOFT)
        ax.margins(y=0.16)

    fig.text(0.5, -0.02, caption(order), fontsize=8, color=MUTED, ha="center")
    fig.suptitle("Obremenitev posrednika po postavitvah", fontsize=13, color=INK,
                 x=0.02, ha="left")
    save(fig, out / "obremenitev.png")


def timeline_chart(rows: list[dict], controller: list[dict], out: Path) -> None:
    if not rows:
        return

    start = min(r["ts"] for r in rows)
    clients = sorted({r["client"] for r in rows})
    fig, ax = figure(size=(11, 4.6))
    style_axes(ax, grid_axis="both")

    for index, client in enumerate(clients):
        color = SLOT[index % len(SLOT)]
        mine = [r for r in rows if r["client"] == client and r.get("time_total") is not None]
        ok = [r for r in mine if not r.get("blocked")]
        hit = [r for r in mine if r.get("blocked")]
        ax.scatter([r["ts"] - start for r in ok], [r["time_total"] * 1000 for r in ok],
                   s=18, color=color, label=client, zorder=2, linewidths=0)
        if hit:
            ax.scatter([r["ts"] - start for r in hit], [r["time_total"] * 1000 for r in hit],
                       s=46, color=color, marker="x", linewidths=1.8, zorder=3)

    for row in (c for c in controller if c.get("source") == "demote" and c.get("changed")):
        moment = row["ts"] - start
        ax.axvline(moment, color=INK_SOFT, linestyle="--", linewidth=1.5, zorder=1)
        ax.annotate(f"{row['src']} → {row['action_after']}", (moment, 0.98),
                    xycoords=ax.get_xaxis_transform(), xytext=(6, -10),
                    textcoords="offset points", fontsize=9, color=INK, va="top")

    ax.set_xlabel("cas od zacetka zagona (s)", fontsize=9, color=INK_SOFT)
    ax.set_ylabel("latenca zahteve (ms)", fontsize=9, color=INK_SOFT)
    ax.margins(y=0.14)
    handles = [Line2D([], [], marker="o", linestyle="", color=SLOT[i % len(SLOT)],
                      markersize=7, label=c) for i, c in enumerate(clients)]
    handles.append(Line2D([], [], marker="x", linestyle="", color=MUTED, markersize=8,
                          markeredgewidth=1.8, label="blokirano po vsebini"))
    ax.legend(handles=handles, frameon=False, fontsize=9, labelcolor=INK_SOFT,
              ncols=4, loc="upper center", bbox_to_anchor=(0.5, -0.14))
    fig.suptitle("Zagon G skozi cas: zaznava zniza zaupanje in preusmeri odjemalca",
                 fontsize=13, color=INK, x=0.02, ha="left")
    save(fig, out / "casovnica.png")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=HERE / "out")
    parser.add_argument("--runs", default="ABCDEFGH")
    args = parser.parse_args(argv)

    names = [n for n in args.runs if n in RUNS]
    metrics = {n: read_jsonl(args.out / n / "metrics.jsonl") for n in names}
    metrics = {n: rows for n, rows in metrics.items() if rows}
    if not metrics:
        raise SystemExit(f"v {args.out} ni nobenega zagona - pozeni compare.sh")

    summaries = {n: read_json(args.out / n / "summary.json") for n in metrics}
    summaries = {n: data for n, data in summaries.items() if data}
    alerts = {n: read_jsonl(args.out / n / "alerts.jsonl") for n in metrics}
    ifstats = {n: read_json(args.out / n / "ifstats.json") for n in metrics}
    ifstats = {n: data for n, data in ifstats.items() if data}
    flows = {n: read_jsonl(args.out / n / "proxy_flows.jsonl") for n in metrics}

    graphs = args.out / "graf"
    global SUBTITLE
    SUBTITLE = describe(metrics, summaries)
    print(f"grafi iz {len(metrics)} zagonov ({SUBTITLE}):")
    if ifstats:
        cost_benefit_chart(metrics, ifstats, graphs)
        load_chart(ifstats, flows, graphs)
    detection_chart(metrics, alerts, graphs)
    latency_chart(summaries, graphs)
    ecdf_chart(metrics, graphs)
    timeline_chart(metrics.get("G", []), read_jsonl(args.out / "G" / "controller.jsonl"), graphs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
