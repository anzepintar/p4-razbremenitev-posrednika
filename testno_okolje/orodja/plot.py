#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
from matplotlib.patches import Patch

HERE = Path(__file__).resolve().parent
OKOLJE = HERE.parent / "okolje"
sys.path.insert(0, str(OKOLJE))
sys.path.insert(0, str(OKOLJE / "client"))

from runner.summarize import as_expected_pct, percentile, responded

NODES = ("client", "switch", "mitm", "server")
NODE_LABELS = {"client": "odjemalec", "switch": "stikalo",
               "mitm": "posrednik", "server": "strežnik"}
MODE_LABELS = {
    "brez": "brez\nposegov",
    "ip_black": "ip\nčrni",
    "ip_white": "ip\nbeli",
    "sni_black": "domenski\nčrni",
    "sni_white": "domenski\nbeli",
    "content_block": "vsebinski\nčrni",
}
PROTO_LABELS = {"h2": "HTTP/2", "h3": "HTTP/3"}
TOPO_NAMES = {"C0": "C", "A0": "A", "B0": "B"}
TOPO_LABELS = {"C0": "C referenca", "A0": "A posrednik", "B0": "B stikalo + posrednik"}

LINK_KEYS = ("rx_packets", "tx_packets", "rx_bytes", "tx_bytes")
SWITCH_KEYS = ("sni_seen", "sni_blocked", "sni_white", "quic",
               "ip_blocked", "ip_white", "denied",
               "quic_sni", "quic_blocked", "quic_white")

# Pricakovana pravilnost. Razclenjevalnik ClientHello v P4 vidi le prvih sest razsiritev
# in preskoci le telesa do MAX_EXT_BODY, zato pri TLS prek TCP nekaj imen po zasnovi ne ujame;
# to ni okvara. Zunanja funkcija za QUIC sestavi okvirje CRYPTO cez datagrame in te meje nima.
OK_FLOOR_DEFAULT = 99.0
OK_FLOOR = {("h2", "sni_black"): 95.0, ("h2", "sni_white"): 95.0}
CLIENT_HEADROOM = 0.8
PAGE_WIDTH = 6.3

plt.rcParams.update({
    "font.size": 9, "axes.titlesize": 9, "axes.labelsize": 9,
    "legend.fontsize": 8, "xtick.labelsize": 8, "ytick.labelsize": 8,
    "pdf.fonttype": 42,
})


def flat(text: str) -> str:
    return text.replace("\n", " ")


def topo_label(topo: str) -> str:
    if topo in TOPO_NAMES:
        return TOPO_NAMES[topo]
    base, _, mode = topo.partition("_")
    if base in TOPO_NAMES and mode:
        return f"{TOPO_NAMES[base]}, {flat(MODE_LABELS.get(mode, mode))}"
    return topo


def series_label(topo: str) -> str:
    return TOPO_LABELS.get(topo) or topo_label(topo)


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


def legend(fig, handles, labels, columns: int) -> None:
    if handles:
        fig.legend(handles, labels, ncols=columns, loc="lower center",
                   bbox_to_anchor=(0.5, below(fig, 0.30)))


def save(fig, stem: str, out: Path, caption: str = "") -> None:
    out.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(out / f"{stem}.pdf", bbox_inches="tight")
    if caption:
        fig.text(0.5, below(fig, 0.62), textwrap.fill(caption, 108),
                 ha="center", va="top", fontsize=7, color="0.35")
    fig.savefig(out / f"{stem}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  {out / stem}.pdf, {stem}.png")


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
    flat = [ax for row in axes for ax in row if ax.has_data()]
    if len(flat) < 2:
        return
    low = min(ax.get_ylim()[0] for ax in flat)
    high = max(ax.get_ylim()[1] for ax in flat)
    for ax in flat:
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
    found = read_json(root / topo / proto / "max.json")
    return found.get("max_rps")


def shares(cells: dict) -> list[int]:
    return sorted({int(name[1:]) for _, _, name in cells
                   if name.startswith("p") and name[1:].isdigit()})


def whole(value: float) -> str:
    return number(value).rstrip("0").rstrip(".") if value % 1 == 0 else number(value)


def conditions(cells: dict, extra: str = "") -> str:
    rates = sorted({c["rate_rps"] for c in cells.values() if c.get("rate_rps")})
    times = sorted({c["window_s"] for c in cells.values() if c.get("window_s")})
    warm = sorted({c["warmup_s"] for c in cells.values() if c.get("warmup_s") is not None})
    parts = []
    if rates:
        parts.append(" in ".join(f"{whole(r)} zahtev/s" for r in rates))
    if times:
        parts.append(" in ".join(f"{whole(s)} s na celico" for s in times))
    if warm:
        parts.append(f"ogrevanje {whole(warm[0])} s")
    if extra:
        parts.append(extra)
    return ("pogoji: " + ", ".join(parts)) if parts else ""


def below_floor(cell: dict | None, proto: str = "", mode: str = "") -> bool:
    ok = (cell or {}).get("policy_ok_pct")
    floor = OK_FLOOR.get((proto, mode), OK_FLOOR_DEFAULT)
    return ok is not None and ok < floor


def bars_chart(cells: dict, stem: str, rows: list[tuple[str, str]], out: Path,
               names: list[str], caption: str = "") -> None:
    topos, protocols = axis(cells, 0), axis(cells, 1)
    panels = [(key, ylabel, proto) for key, ylabel in rows for proto in protocols]
    fig, axes = figure(len(panels), 1, height=2.4)
    hatched_any = False
    for index, (key, ylabel, proto) in enumerate(panels):
        ax = axes[index][0]
        grid(ax)
        width = 0.8 / max(len(topos), 1)
        for order, topo in enumerate(topos):
            offset = (order - (len(topos) - 1) / 2) * width
            heights, hatches, labels = [], [], []
            for name in names:
                cell = cells.get((topo, proto, name))
                value = (cell or {}).get(key)
                heights.append(float("nan") if value is None else value)
                labels.append("" if value is None else number(value))
                hatches.append(below_floor(cell, proto, name))
            drawn = ax.bar([i + offset for i in range(len(names))], heights, width * 0.9,
                           label=series_label(topo))
            for rect, hatched in zip(drawn, hatches):
                if hatched:
                    rect.set_hatch("//")
                    hatched_any = True
            ax.bar_label(drawn, labels=labels, padding=2, fontsize=6.5)
        ax.set_xticks(range(len(names)))
        ax.set_xticklabels([MODE_LABELS.get(n, n) for n in names])
        ax.set_ylabel(ylabel, fontsize=8)
        ax.set_title(PROTO_LABELS.get(proto, proto), loc="left", pad=10)
        ax.margins(y=0.26)
        plain_axis(ax)
    share_scale(axes)

    handles, labels = axes[0][0].get_legend_handles_labels()
    if hatched_any:
        handles.append(Patch(facecolor="white", edgecolor="0.3", hatch="//"))
        labels.append("pravilnost pod pragom")
    legend(fig, handles, labels, len(labels))
    save(fig, stem, out, caption)


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


def search_chart(cells: dict, roots: dict, stem: str, rows: list[tuple[str, str]],
                 out: Path, diagonal: bool = False, caption: str = "") -> None:
    x = rates(cells)
    topos, protocols = axis(cells, 0), axis(cells, 1)
    if not x:
        return
    panels = [(key, ylabel, proto) for key, ylabel in rows for proto in protocols]
    fig, axes = figure(len(rows), len(protocols), height=2.9)
    for index, (key, ylabel, proto) in enumerate(panels):
        ax = axes[index // len(protocols)][index % len(protocols)]
        grid(ax, axis="both")
        seen = sorted({n for n in x if any((topo, proto, f"r{n}") in cells
                                           for topo in topos)})
        if diagonal and seen:
            ax.plot(seen, seen, linestyle=":", color="0.5", label="ponujeno")
        for topo in topos:
            trials = [(n, cells.get((topo, proto, f"r{n}"))) for n in x]
            trials = [(n, c) for n, c in trials if c is not None]
            if not trials:
                continue
            line = ax.plot([n for n, _ in trials], [c.get(key) for _, c in trials],
                           marker="o", label=series_label(topo))
            colour = line[0].get_color()
            for n, c in trials:
                if c.get("ok") is False and c.get(key) is not None:
                    ax.plot([n], [c[key]], marker="o", markersize=9, linestyle="none",
                            color=colour, markerfacecolor="none", markeredgecolor=colour)
            found = max_rps(roots.get(topo, out.parent), topo, proto)
            if found:
                ax.axvline(found, linestyle="--", linewidth=1, color=colour)
        ax.set_xscale("log", base=2)
        marks = [2 ** e for e in range(3, 11)
                 if seen and seen[0] <= 2 ** e <= seen[-1]] or seen
        ax.set_xticks(marks)
        ax.set_xticklabels(marks)
        ax.set_xlabel("ponujenih zahtev/s")
        ax.set_title(PROTO_LABELS.get(proto, proto), loc="left")
        if index % len(protocols) == 0:
            ax.set_ylabel(ylabel)
        plain_axis(ax)
    share_scale(axes)
    legend(fig, *axes[0][0].get_legend_handles_labels(),
           len(topos) + (1 if diagonal else 0))
    save(fig, stem, out, caption)


SEARCH_CAPTION = ("pogoji: poskus 12 s, potrditev 30 s; vzdržno pomeni brez napak in vsaj "
                  "98 % ciljne hitrosti (RFC 2544). Votel znak je padel poskus, "
                  "navpičnica najdena največja vzdržna hitrost.")


def render_search(cells: dict, out: Path, name: str) -> None:
    stem = name.split("_")[0]
    roots = {t: out.parent for t in axis(cells, 0)}
    search_chart(cells, roots, f"{stem}_iskanje",
                 [("requests_s", "doseženih zahtev/s")], out,
                 diagonal=True, caption=SEARCH_CAPTION)
    search_chart(cells, roots, f"{stem}_rokovanje",
                 [("handshake_p50_ms", "rokovanje p50 (ms)"),
                  ("handshake_p95_ms", "rokovanje p95 (ms)")], out,
                 caption=SEARCH_CAPTION)
    node = "switch" if name == "m3_stikalo" else "mitm"
    if any(c.get(f"cpu_ms_per_request_{node}") is not None for c in cells.values()):
        search_chart(cells, roots, f"{stem}_cpu",
                     [(f"cpu_ms_per_request_{node}",
                       f"CPU {NODE_LABELS[node]} (ms/zahtevo)")], out,
                     caption=SEARCH_CAPTION)


def render_referenca(cells: dict, out: Path, name: str) -> None:
    merged, roots = dict(cells), {t: out.parent for t in axis(cells, 0)}
    for other, topo in (("m1_posrednik", "A0"), ("m3_stikalo", "B0")):
        root = out.parent.parent / other
        merged.update(collect(root))
        roots[topo] = root
    search_chart(merged, roots, "m4_referenca",
                 [("requests_s", "doseženih zahtev/s")], out,
                 diagonal=True, caption=SEARCH_CAPTION)
    search_chart(merged, roots, "m4_rokovanje",
                 [("handshake_p50_ms", "rokovanje p50 (ms)"),
                  ("handshake_p95_ms", "rokovanje p95 (ms)")], out,
                 caption=SEARCH_CAPTION)

    header = ["postavitev", "protokol", "največja vzdržna hitrost (zahtev/s)",
              "propustnost pri njej (Mb/s)", "rokovanje p50 (ms)"]
    rows = []
    for topo in axis(merged, 0):
        for proto in axis(merged, 1):
            found = max_rps(roots.get(topo, out.parent), topo, proto)
            confirmed = merged.get((topo, proto, "potrjeno")) or {}
            if found is None and not confirmed:
                continue
            rows.append([topo_label(topo), PROTO_LABELS.get(proto, proto),
                         "-" if found is None else str(found),
                         show(confirmed, "goodput_mbps"),
                         show(confirmed, "handshake_p50_ms")])
    (out.parent / "maksimumi.md").write_text(table(header, rows), encoding="utf-8")
    print(f"  {out.parent / 'maksimumi.md'}")


def render_pravilnost(cells: dict, out: Path, name: str) -> None:
    names = axis(cells, 2)
    caption = conditions(cells, "prag: 95 % za domenski seznam v HTTP/2, sicer 99 %")
    bars_chart(cells, "m2_pravilnost",
               [("policy_ok_pct", "pravilnost (%)")], out, names, caption)

    header = ["postavitev", "protokol", "vrsta prometa", "pravilnost (%)",
              "poslanih zahtev", "sej pri posredniku", "števci stikala"]
    rows = []
    for (topo, proto, mode), cell in cells.items():
        counters = {k: v for k, v in (cell.get("switch") or {}).items() if v}
        rows.append([topo_label(topo), PROTO_LABELS.get(proto, proto), flat(MODE_LABELS.get(mode, mode)),
                     show(cell, "policy_ok_pct"), show(cell, "requests"),
                     show(cell, "proxy_sessions"),
                     ", ".join(f"{k} {v}" for k, v in counters.items()) or "-"])
    (out.parent / "pravilnost.md").write_text(table(header, rows), encoding="utf-8")
    print(f"  {out.parent / 'pravilnost.md'}")


def render_vrste(cells: dict, out: Path, name: str) -> None:
    names = axis(cells, 2)
    caption = conditions(cells, "stalna obremenitev, 70 % manjšega od maksimumov iz m1 in m3; "
                                "ni rampe, ker se ne išče meje, ampak cena pri eni obremenitvi")
    bars_chart(cells, "m5_rokovanje", [("handshake_p50_ms", "rokovanje p50 (ms)"),
                                       ("handshake_p95_ms", "rokovanje p95 (ms)")],
               out, names, caption)
    bars_chart(cells, "m5_breme",
               [("cpu_ms_per_request_mitm", "CPU posrednika (ms/zahtevo)")],
               out, names, caption)


def crossing(a_insp, a_pass, b_insp, b_pass) -> float | None:
    """Delez obhoda, pri katerem breme posrednika v B0 pade pod A0."""
    if None in (a_insp, a_pass, b_insp, b_pass):
        return None
    denominator = (a_insp - a_pass) - (b_insp - b_pass)
    if denominator == 0:
        return None
    return (a_insp - b_insp) / denominator


def bypass_group(cells: dict) -> str:
    for cell in cells.values():
        for part in (cell.get("groups") or "").split(","):
            group = part.split(":")[0].strip()
            if group and group != "unknown":
                return group
    return "sni_white"


def render_prag(cells: dict, out: Path, name: str) -> None:
    pure = collect(out.parent.parent / "m5_vrste")
    if not pure:
        print("  m5_vrste ni izmerjen, zato modela praga ni mogoce izracunati")
        return

    key = "cpu_ms_per_request_mitm"
    mixed = bypass_group(cells)
    protocols = axis(pure, 1)
    mechanisms = [m for m in ("ip_white", "ip_black", "sni_white", "sni_black")
                  if any(k[2] == m for k in pure)]

    rows = []
    fig, axes = figure(1, len(protocols), height=2.9)
    for column, proto in enumerate(protocols):
        ax = axes[0][column]
        grid(ax, axis="both")
        a_insp = (pure.get(("A0", proto, "brez")) or {}).get(key)
        b_insp = (pure.get(("B0", proto, "brez")) or {}).get(key)

        for mechanism in mechanisms:
            a_pass = (pure.get(("A0", proto, mechanism)) or {}).get(key)
            b_pass = (pure.get(("B0", proto, mechanism)) or {}).get(key)
            point = crossing(a_insp, a_pass, b_insp, b_pass)
            rows.append([PROTO_LABELS.get(proto, proto),
                         flat(MODE_LABELS.get(mechanism, mechanism)),
                         *(f"{v:g}" if v is not None else "-"
                           for v in (a_insp, a_pass, b_insp, b_pass)),
                         "-" if point is None else f"{point * 100:.1f} %"
                         if 0 <= point <= 1 else
                         ("vedno" if point < 0 else "nikoli")])

        span = [i / 20 for i in range(21)]
        for topo, insp in (("A0", a_insp), ("B0", b_insp)):
            bypass = (pure.get((topo, proto, mixed)) or {}).get(key)
            if insp is None or bypass is None:
                continue
            drawn = ax.plot(span, [(1 - p) * insp + p * bypass for p in span],
                            label=f"{topo_label(topo)} model")
            xs = [p / 100 for p in shares(cells)]
            ys = [(cells.get((topo, proto, f"p{p}")) or {}).get(key) for p in shares(cells)]
            if any(y is not None for y in ys):
                ax.plot(xs, ys, linestyle="none", marker="o",
                        color=drawn[0].get_color(), label=f"{topo_label(topo)} izmerjeno")

        point = crossing(a_insp, (pure.get(("A0", proto, mixed)) or {}).get(key),
                         b_insp, (pure.get(("B0", proto, mixed)) or {}).get(key))
        if point is not None and 0 <= point <= 1:
            ax.axvline(point, linestyle=":", color="0.4")
            ax.annotate(f"prag {point * 100:.0f} %", (point, ax.get_ylim()[1]),
                        textcoords="offset points", xytext=(3, -10), fontsize=7)
        ax.set_xlabel("delež obhodnega prometa")
        ax.set_title(PROTO_LABELS.get(proto, proto), loc="left")
        if column == 0:
            ax.set_ylabel("CPU posrednika (ms/zahtevo)")
        plain_axis(ax)
    legend(fig, *axes[0][0].get_legend_handles_labels(), 4)
    save(fig, "m6_prag", out,
         conditions(cells, f"premici sta model iz čistih cen v m5 za {flat(MODE_LABELS.get(mixed, mixed))}, "
                           "točke pa izmerjene mešanice; ni rampe, ker se meri cena pri eni obremenitvi"))

    header = ["protokol", "mehanizem", "A pregled", "A obhod", "B pregled", "B obhod",
              "prag"]
    (out.parent / "prag.md").write_text(table(header, rows), encoding="utf-8")
    print(f"  {out.parent / 'prag.md'}")


LIMIT_CAPTION = ("pogoji: iskanje po RFC 2544, poskus 12 s, potrditev 30 s; tok je v celoti "
                 "ene vrste prometa. Stolpec brez posegov je iz m1 in m3.")


def render_zmogljivost(cells: dict, out: Path, name: str) -> None:
    root = out.parent
    roots = {t: root for t in axis(cells, 0)}
    search_chart(cells, roots, "m7_iskanje",
                 [("requests_s", "doseženih zahtev/s")], out,
                 diagonal=True, caption=SEARCH_CAPTION)

    protocols = axis(cells, 1)
    seen = {t.partition("_")[2] for t in axis(cells, 0) if "_" in t}
    names = ["brez"] + [m for m in MODE_LABELS if m in seen]
    base = {"A0": root.parent / "m1_posrednik", "B0": root.parent / "m3_stikalo"}

    limits, pool = {}, dict(cells)
    for source in base.values():
        pool.update(collect(source))
    for topo in ("A0", "B0"):
        for proto in protocols:
            for mode in names:
                where = base[topo] if mode == "brez" else root
                key = topo if mode == "brez" else f"{topo}_{mode}"
                found = max_rps(where, key, proto)
                if found:
                    limits[(topo, proto, mode)] = {"max_rps": found}
    if not limits:
        return

    bars_chart(limits, "m7_meja",
               [("max_rps", "največja vzdržna hitrost (zahtev/s)")],
               out, names, LIMIT_CAPTION)

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
                key = topo if mode == "brez" else f"{topo}_{mode}"
                confirmed = pool.get((key, proto, "potrjeno")) or {}
                rows.append([topo_label(topo), PROTO_LABELS.get(proto, proto),
                             flat(MODE_LABELS.get(mode, mode)), str(found),
                             show(confirmed, "goodput_mbps"),
                             show(confirmed, "cpu_ms_per_request_mitm"),
                             show(confirmed, "cpu_ms_per_request_switch")])
    (root / "maksimumi_vrste.md").write_text(table(header, rows), encoding="utf-8")
    print(f"  {root / 'maksimumi_vrste.md'}")


RENDERERS = {
    "m1_posrednik": render_search,
    "m2_pravilnost": render_pravilnost,
    "m3_stikalo": render_search,
    "m4_referenca": render_referenca,
    "m5_vrste": render_vrste,
    "m6_prag": render_prag,
    "m7_zmogljivost": render_zmogljivost,
}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    roots = [Path(a) for a in argv] or sorted(
        d for d in (OKOLJE / "out").glob("m[0-9]_*") if d.is_dir())
    if not roots:
        raise SystemExit("plot.py: podaj imenik meritve, npr. okolje/out/m1_posrednik")

    for root in roots:
        cells = collect(root)
        if not cells:
            print(f"{root}: ni meritev")
            continue
        print(f"{root.name}: {len(cells)} celic")
        out = root / "graf"
        RENDERERS.get(root.name, render_search)(cells, out, root.name)
        (root / "results.md").write_text(results_table(cells), encoding="utf-8")
        (root / "veljavnost.md").write_text(validity_table(cells), encoding="utf-8")
        (root / "results.json").write_text(
            json.dumps({"/".join(k): v for k, v in cells.items()},
                       indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
        print(f"  {root / 'results.md'}, veljavnost.md, results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
