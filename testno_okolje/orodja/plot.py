#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
OKOLJE = HERE.parent / "okolje"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(OKOLJE))
sys.path.insert(0, str(OKOLJE / "client"))

import counters
import maxrps
from nodestats import NODES
from runner.summarize import as_expected_pct, percentile, responded

MODE_LABELS = {
    "brez": "brez\nposegov",
    "ip_black": "črni\nIP",
    "ip_white": "beli\nIP",
    "sni_black": "črni\ndomenski",
    "sni_white": "beli\ndomenski",
    "content_block": "vsebinski\nčrni",
}
PROTO_LABELS = {"h2": "HTTP/2", "h3": "HTTP/3"}
TOPO_LABELS = {"C0": "C", "A0": "A", "B0": "B"}

LINK_KEYS = ("rx_packets", "tx_packets", "rx_bytes", "tx_bytes")
SWITCH_KEYS = counters.NAMES

# Mehanizma, pri katerih promet obide posrednika in ju zato meri m6_prag.
MECHANISMS = ("ip_white", "sni_white")

PAGE_WIDTH = 6.3

plt.rcParams.update({
    "font.size": 9, "axes.titlesize": 9, "axes.labelsize": 9,
    "legend.fontsize": 8, "xtick.labelsize": 8, "ytick.labelsize": 8,
    "pdf.fonttype": 42,
})


def flat(text: str) -> str:
    return text.replace("\n", " ")


def topo_label(topo: str) -> str:
    if topo in TOPO_LABELS:
        return TOPO_LABELS[topo]
    base, _, mode = topo.partition("_")
    if base in TOPO_LABELS and mode:
        return f"{TOPO_LABELS[base]}, {flat(MODE_LABELS.get(mode, mode))}"
    return topo


def read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def figure(rows: int = 1, cols: int = 1, height: float = 2.4):
    fig, axes = plt.subplots(rows, cols, figsize=(PAGE_WIDTH, height * rows), squeeze=False)
    return fig, axes


def grid(ax, axis: str = "y") -> None:
    ax.grid(True, axis=axis)
    ax.set_axisbelow(True)


def below(fig, inches: float) -> float:
    """Odmik pod sliko v stalni fizicni razdalji, ne glede na visino slike."""
    return -inches / fig.get_figheight()


def legend(fig, axes) -> None:
    """Postavke iz vseh plosc, ker jih prva ne nosi nujno vseh."""
    handles, labels = [], []
    for row in axes:
        for ax in row:
            for handle, label in zip(*ax.get_legend_handles_labels()):
                if label not in labels:
                    handles.append(handle)
                    labels.append(label)
    if handles:
        fig.legend(handles, labels, ncols=len(labels), loc="lower center",
                   bbox_to_anchor=(0.5, below(fig, 0.30)))


def save(fig, stem: str, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(out / f"{stem}.pdf", bbox_inches="tight")
    plt.close(fig)
    print(f"  {out / stem}.pdf")


def number(value: float) -> str:
    """Zapis brez eksponenta; decimalke po velikosti."""
    size = abs(value)
    if size >= 100:
        return f"{value:,.0f}".replace(",", " ")
    if size >= 10:
        return f"{value:.1f}"
    if size >= 1:
        return f"{value:.2f}"
    if size > 0:
        return f"{value:.3f}"
    return "0"


def plain_axis(ax) -> None:
    ax.ticklabel_format(style="plain", axis="y", useOffset=False)


def share_scale(axes) -> None:
    """Obe plosci na sliki dobita isto os y, da sta neposredno primerljivi."""
    drawn = [ax for row in axes for ax in row if ax.has_data()]
    if len(drawn) < 2:
        return
    low = min(ax.get_ylim()[0] for ax in drawn)
    high = max(ax.get_ylim()[1] for ax in drawn)
    for ax in drawn:
        ax.set_ylim(low, high)


def share_columns(axes) -> None:
    """Skupna os y po stolpcu; skupna cez oba protokola bi stisnila plosco HTTP/2."""
    for column in range(len(axes[0])):
        drawn = [row[column] for row in axes if row[column].has_data()]
        if len(drawn) < 2:
            continue
        low = min(ax.get_ylim()[0] for ax in drawn)
        high = max(ax.get_ylim()[1] for ax in drawn)
        for ax in drawn:
            ax.set_ylim(low, high)


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


def cpu_delta(before: dict, after: dict) -> dict:
    out: dict = {}
    for node, values in after.items():
        was = before.get(node) or {}
        out[node] = {
            "cpu_ms": max(0, values.get("usage_usec", 0) - was.get("usage_usec", 0)) / 1000,
            "quota": values.get("cpu_quota"),
        }
    return out


def counter_delta(before: dict, after: dict) -> dict:
    if not after:
        return {}
    return {key: max(0, after.get(key, 0) - before.get(key, 0)) for key in SWITCH_KEYS}


def after_warmup(rows: list[dict], warmup_s: float) -> list[dict]:
    stamps = [r["ts"] for r in rows if r.get("ts") is not None]
    if not stamps or warmup_s <= 0:
        return rows
    start = min(stamps) + warmup_s
    return [r for r in rows if (r.get("ts") or 0) >= start]


def load_cell(directory: Path) -> dict | None:
    every = read_jsonl(directory / "metrics.jsonl")
    if not every:
        return None
    meta = read_json(directory / "meta.json")
    window = float(meta.get("duration_s") or 0)
    warmup = float(meta.get("warmup_s") or 0)
    seconds = window - warmup
    if seconds <= 0:
        return None

    rows = after_warmup(every, warmup)
    allowed = [r for r in rows if not r.get("expect_blocked")]
    ok = responded(allowed)
    errors = sum(1 for r in allowed if r.get("exitcode") != 0)
    appconnect = [r["time_appconnect"] for r in ok if r.get("time_appconnect") is not None]

    links = link_delta(read_json(directory / "links_before.json"),
                       read_json(directory / "links_after.json"))
    cpu = cpu_delta(read_json(directory / "cpu_before.json"),
                    read_json(directory / "cpu_after.json"))
    proxy_bytes = (links.get("mitm") or {}).get("rx_bytes", 0)
    sent = len(rows)

    cell = {
        "goodput_mbps": round(sum(r.get("size_download") or 0 for r in allowed)
                              * 8 / seconds / 1e6, 2),
        "handshake_p50_ms": ms(percentile(appconnect, 50)),
        "handshake_p95_ms": ms(percentile(appconnect, 95)),
        "total_p50_ms": ms(percentile([r["time_total"] for r in ok], 50)),
        "total_p95_ms": ms(percentile([r["time_total"] for r in ok], 95)),
        "requests": sent,
        "requests_s": round(sent / seconds, 1),
        "proxy_kb_per_request": round(proxy_bytes / 1024 / sent, 2) if sent else None,
        "policy_ok_pct": as_expected_pct(rows),
        "proxy_sessions": len(read_jsonl(directory / "proxy_flows.jsonl")),
        "errors_pct": round(errors / len(allowed) * 100, 2) if allowed else None,
        "duration_s": seconds,
        "window_s": window,
        "warmup_s": warmup,
        "rate_rps": meta.get("rate_rps"),
        "workers": meta.get("workers"),
        "groups": meta.get("groups"),
        "switch": counter_delta(read_json(directory / "switch_before.json"),
                                read_json(directory / "switch_after.json")),
    }
    for node in NODES:
        values = cpu.get(node)
        total = round(values["cpu_ms"], 3) if values else None
        cores = round(total / window / 1000, 3) if total is not None else None
        quota = (values or {}).get("quota")
        cell[f"cpu_ms_per_request_{node}"] = (round(total / sent, 4)
                                              if total is not None and sent else None)
        cell[f"cpu_util_{node}"] = round(cores / quota, 3) if cores and quota else None
    return cell


def collect(root: Path) -> dict:
    cells: dict = {}
    for directory in sorted(root.glob("*/*/*")):
        if not directory.is_dir():
            continue
        cell = load_cell(directory)
        if cell is not None:
            topo, proto, name = directory.parts[-3:]
            cell["ok"] = read_json(directory / "verdict.json").get("ok")
            cells[(topo, proto, name)] = cell
    return cells


def axis(cells: dict, index: int) -> list:
    seen = []
    for key in cells:
        if key[index] not in seen:
            seen.append(key[index])
    if index == 0:
        return [t for t in TOPO_LABELS if t in seen] + [t for t in seen if t not in TOPO_LABELS]
    if index == 2:
        return [m for m in MODE_LABELS if m in seen] + [m for m in seen if m not in MODE_LABELS]
    return seen


def rates(cells: dict) -> list[int]:
    return sorted({int(name[1:]) for _, _, name in cells
                   if name.startswith("r") and name[1:].isdigit()})


def max_rps(root: Path, topo: str, proto: str) -> int | None:
    return maxrps.read(root / topo / proto)


def mix_points(cells: dict, mechanism: str) -> list[int]:
    """Delezi obhoda iz imen celic oblike <mehanizem>_p<delez>."""
    head = f"{mechanism}_p"
    return sorted({int(name[len(head):]) for _, _, name in cells
                   if name.startswith(head) and name[len(head):].isdigit()})


def whole(value: float) -> str:
    return number(value).rstrip("0").rstrip(".") if value % 1 == 0 else number(value)


def rate_note(cells: dict, proto: str) -> str:
    """Privzeta obremenitev spada v naslov plosce; pri iskanju je ni, ker se hitrost menja."""
    found = sorted({c["rate_rps"] for (_, p, _), c in cells.items()
                    if p == proto and c.get("rate_rps")})
    return f" ({whole(found[0])} zahtev/s)" if len(found) == 1 else ""


def panel_title(cells: dict, proto: str) -> str:
    return PROTO_LABELS.get(proto, proto) + rate_note(cells, proto)


def bars_chart(cells: dict, stem: str, key: str, ylabel: str, out: Path,
               names: list[str]) -> None:
    topos, protocols = axis(cells, 0), axis(cells, 1)
    fig, axes = figure(len(protocols), 1, height=2.4)
    for index, proto in enumerate(protocols):
        ax = axes[index][0]
        grid(ax)
        width = 0.8 / max(len(topos), 1)
        for order, topo in enumerate(topos):
            offset = (order - (len(topos) - 1) / 2) * width
            heights, labels = [], []
            for name in names:
                value = (cells.get((topo, proto, name)) or {}).get(key)
                heights.append(float("nan") if value is None else value)
                labels.append("" if value is None else number(value))
            drawn = ax.bar([i + offset for i in range(len(names))], heights, width * 0.9,
                           label=topo_label(topo))
            ax.bar_label(drawn, labels=labels, padding=2, fontsize=6.5)
        ax.set_xticks(range(len(names)))
        ax.set_xticklabels([MODE_LABELS.get(n, n) for n in names])
        ax.set_ylabel(ylabel, fontsize=8)
        ax.set_title(panel_title(cells, proto), loc="left", pad=10)
        ax.margins(y=0.26)
        plain_axis(ax)
    share_scale(axes)
    legend(fig, axes)
    save(fig, stem, out)


def search_chart(cells: dict, stem: str, out: Path) -> None:
    x = rates(cells)
    if not x:
        return
    topos, protocols = axis(cells, 0), axis(cells, 1)
    fig, axes = figure(1, len(protocols), height=2.9)
    for column, proto in enumerate(protocols):
        ax = axes[0][column]
        grid(ax, axis="both")
        seen = sorted({n for n in x if any((topo, proto, f"r{n}") in cells for topo in topos)})
        if seen:
            ax.plot(seen, seen, linestyle=":", color="0.5", label="ponujeno")
        for topo in topos:
            trials = [(n, cells[(topo, proto, f"r{n}")]) for n in x
                      if (topo, proto, f"r{n}") in cells]
            if not trials:
                continue
            line = ax.plot([n for n, _ in trials], [c.get("requests_s") for _, c in trials],
                           marker="o", label=topo_label(topo))
            colour = line[0].get_color()
            for n, cell in trials:
                if cell.get("ok") is False and cell.get("requests_s") is not None:
                    ax.plot([n], [cell["requests_s"]], marker="o", markersize=9,
                            linestyle="none", color=colour,
                            markerfacecolor="none", markeredgecolor=colour)
            found = max_rps(out.parent, topo, proto)
            if found:
                ax.axvline(found, linestyle="--", linewidth=1, color=colour)
        ax.set_xscale("log", base=2)
        marks = [2 ** e for e in range(3, 12)
                 if seen and seen[0] <= 2 ** e <= seen[-1]] or seen
        ax.set_xticks(marks)
        ax.set_xticklabels(marks)
        ax.set_xlabel("ponujenih zahtev/s")
        ax.set_title(PROTO_LABELS.get(proto, proto), loc="left")
        if column == 0:
            ax.set_ylabel("doseženih zahtev/s")
        plain_axis(ax)
    share_scale(axes)
    legend(fig, axes)
    save(fig, stem, out)


def table(header: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(header) + " |",
           "| " + " | ".join([":---"] * len(header)) + " |"]
    out += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(out) + "\n"


def show(cell: dict, key: str) -> str:
    value = cell.get(key)
    return "-" if value is None else number(value)


REPORT_KEYS = (
    ("goodput_mbps", "propustnost (Mb/s)"),
    ("total_p95_ms", "latenca p95 (ms)"),
    ("handshake_p50_ms", "rokovanje p50 (ms)"),
    ("handshake_p95_ms", "rokovanje p95 (ms)"),
    ("cpu_ms_per_request_mitm", "CPU posrednika (ms/zahtevo)"),
    ("cpu_ms_per_request_switch", "CPU stikala (ms/zahtevo)"),
    ("proxy_kb_per_request", "promet do posrednika (kB/zahtevo)"),
    ("requests", "poslanih zahtev"),
    ("policy_ok_pct", "pravilnost (%)"),
)


def results_table(cells: dict) -> str:
    header = ["postavitev", "protokol", "celica"] + [label for _, label in REPORT_KEYS]
    rows = [[topo_label(topo), PROTO_LABELS.get(proto, proto), name]
            + [show(cell, key) for key, _ in REPORT_KEYS]
            for (topo, proto, name), cell in cells.items()]
    return table(header, rows)


def validity_table(cells: dict) -> str:
    header = ["postavitev", "protokol", "celica", "napake (%)", "poslanih zahtev",
              "izraba odjemalca", "izraba posrednika", "izraba stikala"]
    keys = ["errors_pct", "requests", "cpu_util_client", "cpu_util_mitm", "cpu_util_switch"]
    rows = [[topo_label(topo), PROTO_LABELS.get(proto, proto), name]
            + [show(cell, key) for key in keys]
            for (topo, proto, name), cell in cells.items()]
    return table(header, rows)


def render_oprema(cells: dict, out: Path, name: str) -> None:
    search_chart(cells, "m1_oprema", out)


def render_stikalo(cells: dict, out: Path, name: str) -> None:
    search_chart(cells, "m2_stikalo", out)


def render_pravilnost(cells: dict, out: Path, name: str) -> None:
    bars_chart(cells, "m3_pravilnost", "policy_ok_pct", "pravilnost (%)",
               out, axis(cells, 2))

    header = ["postavitev", "protokol", "vrsta prometa", "pravilnost (%)",
              "poslanih zahtev", "sej pri posredniku", "števci stikala"]
    rows = []
    for (topo, proto, mode), cell in cells.items():
        seen = {k: v for k, v in (cell.get("switch") or {}).items() if v}
        rows.append([topo_label(topo), PROTO_LABELS.get(proto, proto),
                     flat(MODE_LABELS.get(mode, mode)),
                     show(cell, "policy_ok_pct"), show(cell, "requests"),
                     show(cell, "proxy_sessions"),
                     ", ".join(f"{k} {v}" for k, v in seen.items()) or "-"])
    (out.parent / "pravilnost.md").write_text(table(header, rows), encoding="utf-8")
    print(f"  {out.parent / 'pravilnost.md'}")


def render_vrste(cells: dict, out: Path, name: str) -> None:
    bars_chart(cells, "m4_vrste", "cpu_ms_per_request_mitm",
               "CPU posrednika (ms/zahtevo)", out, axis(cells, 2))


def render_zmogljivost(cells: dict, out: Path, name: str) -> None:
    root = out.parent
    protocols = axis(cells, 1)
    seen = {t.partition("_")[2] for t in axis(cells, 0) if "_" in t}
    names = [m for m in MODE_LABELS if m in seen]

    limits = {}
    for topo in ("A0", "B0"):
        for proto in protocols:
            for mode in names:
                found = max_rps(root, f"{topo}_{mode}", proto)
                if found:
                    limits[(topo, proto, mode)] = {"max_rps": found}
    if not limits:
        return

    bars_chart(limits, "m5_zmogljivost", "max_rps",
               "največja vzdržna hitrost (zahtev/s)", out, names)

    header = ["postavitev", "protokol", "vrsta prometa",
              "največja vzdržna hitrost (zahtev/s)", "propustnost pri njej (Mb/s)",
              "CPU posrednika (ms/zahtevo)", "CPU stikala (ms/zahtevo)"]
    rows = []
    for topo in ("A0", "B0"):
        for proto in protocols:
            for mode in names:
                found = (limits.get((topo, proto, mode)) or {}).get("max_rps")
                if found is None:
                    continue
                confirmed = cells.get((f"{topo}_{mode}", proto, "potrjeno")) or {}
                rows.append([topo_label(topo), PROTO_LABELS.get(proto, proto),
                             flat(MODE_LABELS.get(mode, mode)), str(found),
                             show(confirmed, "goodput_mbps"),
                             show(confirmed, "cpu_ms_per_request_mitm"),
                             show(confirmed, "cpu_ms_per_request_switch")])
    (root / "maksimumi_vrste.md").write_text(table(header, rows), encoding="utf-8")
    print(f"  {root / 'maksimumi_vrste.md'}")


def crossing(a_insp, a_pass, b_insp, b_pass) -> float | None:
    """Delez obhoda, pri katerem breme posrednika v B0 pade pod A0."""
    if None in (a_insp, a_pass, b_insp, b_pass):
        return None
    denominator = (a_insp - a_pass) - (b_insp - b_pass)
    if denominator == 0:
        return None
    return (a_insp - b_insp) / denominator


def threshold_label(a_insp, a_pass, b_insp, b_pass) -> str:
    """Prag kot besedilo. Zunaj [0, 1] premici v razponu ne trcita, zato odloci razvrstitev
    pri niclemu obhodu: sign presecisca sam po sebi ne pove, katera postavitev je cenejsa."""
    if None in (a_insp, a_pass, b_insp, b_pass):
        return "-"
    point = crossing(a_insp, a_pass, b_insp, b_pass)
    if point is not None and 0 <= point <= 1:
        return f"{point * 100:.1f} %"
    if b_insp == a_insp:
        return "vedno" if b_pass < a_pass else "nikoli"
    return "vedno" if b_insp < a_insp else "nikoli"


def anchors(cells: dict, proto: str, mechanism: str) -> dict:
    """Cisti ceni pri niclemu in polnem obhodu, iz katerih tece modelna premica."""
    key = "cpu_ms_per_request_mitm"
    return {topo: ((cells.get((topo, proto, f"{mechanism}_p0")) or {}).get(key),
                   (cells.get((topo, proto, f"{mechanism}_p100")) or {}).get(key))
            for topo in ("A0", "B0")}


def render_prag(cells: dict, out: Path, name: str) -> None:
    key = "cpu_ms_per_request_mitm"
    protocols = axis(cells, 1)
    drawn = [m for m in MECHANISMS if mix_points(cells, m)]
    if not drawn:
        return

    fig, axes = figure(len(drawn), len(protocols), height=2.6)
    for row, mechanism in enumerate(drawn):
        inner = [p for p in mix_points(cells, mechanism) if 0 < p < 100]
        for column, proto in enumerate(protocols):
            ax = axes[row][column]
            grid(ax, axis="both")
            ends = anchors(cells, proto, mechanism)
            span = [i / 20 for i in range(21)]
            for topo, (insp, bypass) in ends.items():
                if insp is None or bypass is None:
                    continue
                line = ax.plot(span, [(1 - p) * insp + p * bypass for p in span],
                               label=f"{topo_label(topo)} model")
                ys = [(cells.get((topo, proto, f"{mechanism}_p{p}")) or {}).get(key)
                      for p in inner]
                if any(y is not None for y in ys):
                    ax.plot([p / 100 for p in inner], ys, linestyle="none", marker="o",
                            color=line[0].get_color(),
                            label=f"{topo_label(topo)} izmerjeno")

            point = crossing(*ends["A0"], *ends["B0"])
            if point is not None and 0 <= point <= 1:
                ax.axvline(point, linestyle=":", color="0.4")
                ax.annotate(f"prag {point * 100:.0f} %", (point, 1.0),
                            xycoords=("data", "axes fraction"),
                            textcoords="offset points", xytext=(3, -10), fontsize=7)
            ax.set_title(f"{flat(MODE_LABELS.get(mechanism, mechanism))}, "
                         f"{panel_title(cells, proto)}", loc="left")
            if row == len(drawn) - 1:
                ax.set_xlabel("delež obhodnega prometa")
            if column == 0:
                ax.set_ylabel("CPU posrednika (ms/zahtevo)")
            plain_axis(ax)
    share_columns(axes)
    legend(fig, axes)
    save(fig, "m6_prag", out)

    header = ["protokol", "mehanizem", "A pregled", "A obhod", "B pregled", "B obhod", "prag"]
    rows = []
    for proto in protocols:
        for mechanism in drawn:
            ends = anchors(cells, proto, mechanism)
            rows.append([PROTO_LABELS.get(proto, proto),
                         flat(MODE_LABELS.get(mechanism, mechanism)),
                         *(f"{v:g}" if v is not None else "-"
                           for v in (*ends["A0"], *ends["B0"])),
                         threshold_label(*ends["A0"], *ends["B0"])])
    (out.parent / "prag.md").write_text(table(header, rows), encoding="utf-8")
    print(f"  {out.parent / 'prag.md'}")


RENDERERS = {
    "m1_oprema": render_oprema,
    "m2_stikalo": render_stikalo,
    "m3_pravilnost": render_pravilnost,
    "m4_vrste": render_vrste,
    "m5_zmogljivost": render_zmogljivost,
    "m6_prag": render_prag,
}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    roots = [Path(a) for a in argv] or sorted(
        d for d in (OKOLJE / "out").glob("m[0-9]_*") if d.is_dir())
    if not roots:
        raise SystemExit("plot.py: podaj imenik meritve, npr. okolje/out/m2_stikalo")

    for root in roots:
        cells = collect(root)
        if not cells:
            print(f"{root}: ni meritev")
            continue
        print(f"{root.name}: {len(cells)} celic")
        render = RENDERERS.get(root.name)
        if render is None:
            print(f"  {root.name} ni med meritvami, zato slike ni; tabele vseeno zapisem")
        else:
            render(cells, root / "graf", root.name)
        (root / "results.md").write_text(results_table(cells), encoding="utf-8")
        (root / "veljavnost.md").write_text(validity_table(cells), encoding="utf-8")
        (root / "results.json").write_text(
            json.dumps({"/".join(k): v for k, v in cells.items()},
                       indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
        print(f"  {root / 'results.md'}, veljavnost.md, results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
