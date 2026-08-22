#!/usr/bin/env python3
"""Tabele iz pregleda sto najbolj obiskanih strani.

Bere obe fazi pregleda (C1 kot izhodisce in B1 kot merjeno postavitev) ter iz njiju
sestavi tabele za poglavje o pravem prometu in seznam strani, ki delujejo brez
prestrezanja in z njim ne. Grafov ne rise, ker so izidi stevni in ne zvezni.

    ./orodja/splet_report.py okolje/out/splet
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OKOLJE = HERE.parent / "okolje"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(OKOLJE))
sys.path.insert(0, str(OKOLJE / "client"))

from plot import (PROTO_LABELS, counter_delta, number, read_json, read_jsonl,
                  table)
from probe.verdicts import CLIENTS, PROTOCOLS, server_error

BASE, MEASURED = "C1", "B1"
PROXY_WINDOW_S = 5.0

SWITCH_COLUMNS = ("sni_seen", "sni_blocked", "sni_white", "quic",
                  "quic_sni", "quic_white", "quic_blocked", "denied")


def pct(part: int, whole: int) -> str:
    return f"{number(part / whole * 100)} %" if whole else "-"


def load_probes(root: Path, phase: str) -> dict[tuple[str, str, str], dict]:
    rows: dict[tuple[str, str, str], dict] = {}
    for path in sorted((root / phase).glob("probes_*.jsonl")):
        for item in read_jsonl(path):
            rows[(item["client"], item["proto"], item["domain"])] = recheck(item)
    return rows


def recheck(item: dict) -> dict:
    """Znova uveljavi merilo nad zapisano vrstico.

    Vrstice nosijo vse, kar je za razsodbo potrebno, zato se stroznje merilo pozna
    tudi na ze zbranih podatkih in pregleda ni treba ponoviti.
    """
    if not item.get("ok"):
        return item
    failure = server_error(item.get("http_code"), item.get("title"))
    if failure:
        item = {**item, "ok": False, "error": failure,
                "message": "odgovor je napaka streznika ali posrednika"}
    return item


def present(rows: dict, index: int, order: tuple[str, ...]) -> list[str]:
    seen = {key[index] for key in rows}
    return [name for name in order if name in seen] or sorted(seen)


def cells(base: dict, measured: dict) -> dict[tuple[str, str], dict]:
    """Za vsak par odjemalec-protokol presteje izhodisce, izid in odstopanja."""
    out: dict[tuple[str, str], dict] = {}
    for client in present(base or measured, 0, CLIENTS):
        for proto in present(base or measured, 1, PROTOCOLS):
            domains = sorted({key[2] for key in base if key[:2] == (client, proto)}
                             | {key[2] for key in measured if key[:2] == (client, proto)})
            if not domains:
                continue
            works_base, works_both, broken, recovered = 0, 0, [], []
            for domain in domains:
                first = base.get((client, proto, domain))
                second = measured.get((client, proto, domain))
                ok_base = bool(first and first.get("ok"))
                ok_measured = bool(second and second.get("ok"))
                works_base += ok_base
                if ok_base and ok_measured:
                    works_both += 1
                elif ok_base:
                    broken.append(second or {"domain": domain, "error": "ni poskusa"})
                elif ok_measured:
                    recovered.append(second)
            out[(client, proto)] = {
                "probed": len(domains),
                "base_ok": works_base,
                "measured_ok": works_both,
                "broken": broken,
                "recovered": recovered,
                "base_fail": [base[(client, proto, d)] for d in domains
                              if (client, proto, d) in base
                              and not base[(client, proto, d)].get("ok")],
            }
    return out


def main_table(matrix: dict) -> str:
    header = ["odjemalec", "protokol", f"deluje v {BASE}", f"deluje v {MEASURED}", "delez"]
    rows = [[client, PROTO_LABELS.get(proto, proto),
             str(cell["base_ok"]), str(cell["measured_ok"]),
             pct(cell["measured_ok"], cell["base_ok"])]
            for (client, proto), cell in sorted(matrix.items())]
    return table(header, rows)


def coverage_table(matrix: dict, reachable: int) -> str:
    """Koliksen delez nabora sploh odgovori po posameznem protokolu."""
    header = ["odjemalec", "protokol", "dosegljivih", f"deluje v {BASE}", "delez nabora"]
    rows = [[client, PROTO_LABELS.get(proto, proto), str(reachable),
             str(cell["base_ok"]), pct(cell["base_ok"], reachable)]
            for (client, proto), cell in sorted(matrix.items())]
    return table(header, rows)


def reasons_table(matrix: dict, field: str, caption: str) -> str:
    counted: dict[tuple[str, str, str], int] = {}
    for (client, proto), cell in matrix.items():
        for item in cell[field]:
            reason = item.get("error") or "brez razloga"
            counted[(client, proto, reason)] = counted.get((client, proto, reason), 0) + 1
    if not counted:
        return f"{caption.rstrip(':')}: ni takih strani.\n"
    rows = [[client, PROTO_LABELS.get(proto, proto), reason, str(count)]
            for (client, proto, reason), count in
            sorted(counted.items(), key=lambda item: (item[0][0], item[0][1], -item[1]))]
    return f"{caption}\n\n" + table(["odjemalec", "protokol", "razlog", "strani"], rows)


def switch_table(root: Path, matrix: dict) -> str:
    """Razsodbe stikala po blokih. Za curl je en poskus priblizno ena povezava, zato
    razmerje pove, pri kolikem delezu pravih sporocil ClientHello je stikalo ime res
    prebralo; brskalnik odpre vec povezav na stran, zato je tam razmerje vecje od 1."""
    rows = []
    for (client, proto), cell in sorted(matrix.items()):
        before = read_json(root / MEASURED / f"switch_{client}_{proto}_before.json")
        after = read_json(root / MEASURED / f"switch_{client}_{proto}_after.json")
        delta = counter_delta(before, after)
        if not delta:
            continue
        seen = delta.get("quic_sni" if proto == "h3" else "sni_seen", 0)
        rows.append([client, PROTO_LABELS.get(proto, proto)]
                    + [str(delta.get(key, 0)) for key in SWITCH_COLUMNS]
                    + [pct(seen, cell["probed"])])
    if not rows:
        return "Stevcev stikala ni; ali je bila postavitev B1 res s stikalom?\n"
    header = ["odjemalec", "protokol"] + list(SWITCH_COLUMNS) + ["imen na poskus"]
    return table(header, rows)


def proxy_index(root: Path) -> dict[str, list[dict]]:
    by_host: dict[str, list[dict]] = {}
    for item in read_jsonl(root / MEASURED / "proxy_flows.jsonl"):
        by_host.setdefault(item.get("host") or "", []).append(item)
    return by_host


def proxy_saw(index: dict, item: dict) -> str:
    """Ali je posrednik sejo za to domeno v tem oknu sploh videl in v kateri
    razlicici. Neodvisen vir proti temu, kar poroca odjemalec."""
    start = item.get("ts") or 0
    end = start + (item.get("elapsed_ms") or 0) / 1000 + PROXY_WINDOW_S
    hits = [flow for flow in index.get(item.get("host") or "", [])
            if start - 1 <= (flow.get("ts") or 0) <= end]
    if not hits:
        return "ne"
    versions = sorted({flow.get("http_version") or flow.get("kind") or "?"
                       for flow in hits})
    return ", ".join(versions)


def broken_report(root: Path, matrix: dict) -> str:
    index = proxy_index(root)
    header = ["rang", "domena", "gostitelj", "kategorija", "odjemalec", "protokol",
              "napaka", "sporocilo", "izdajatelj", "posrednik videl"]
    rows = []
    for (client, proto), cell in sorted(matrix.items()):
        for item in sorted(cell["broken"], key=lambda row: row.get("rank") or 0):
            rows.append([
                str(item.get("rank") or "-"),
                item.get("domain") or "-",
                item.get("host") or "-",
                (item.get("categories") or "-").replace("|", "/"),
                client,
                PROTO_LABELS.get(proto, proto),
                item.get("error") or "-",
                (item.get("message") or "-").replace("|", "/")[:120],
                (item.get("issuer") or "-").replace("|", "/"),
                proxy_saw(index, item),
            ])

    text = [f"# Strani, ki delujejo v {BASE} in ne delujejo v {MEASURED}", ""]
    if not rows:
        text += ["Ni takih strani: vse, kar dela brez prestrezanja, dela tudi z njim.", ""]
        return "\n".join(text)
    text += [f"Skupaj {len(rows)} primerov. Izdajatelj `mitmproxy` pomeni desifrirano sejo,",
             "izdajatelj pravega overitelja pa obvod ali neprestrezeno povezavo.", "",
             table(header, rows)]

    recovered = [(client, proto, item) for (client, proto), cell in sorted(matrix.items())
                 for item in cell["recovered"]]
    if recovered:
        text += ["", f"## Deluje v {MEASURED}, v {BASE} pa ne", "",
                 "Take strani so najverjetneje raztros omrezja in ne izid postavitve.", "",
                 table(["domena", "odjemalec", "protokol"],
                       [[item.get("domain") or "-", client, PROTO_LABELS.get(proto, proto)]
                        for client, proto, item in recovered])]
    return "\n".join(text) + "\n"


def report(root: Path) -> int:
    base, measured = load_probes(root, BASE), load_probes(root, MEASURED)
    if not measured:
        print(f"splet_report: v {root / MEASURED} ni pregledov", file=sys.stderr)
        return 1

    targets = read_json(root / "cilji.json").get("targets") or []
    reachable = sum(1 for item in targets if item.get("reachable"))
    matrix = cells(base, measured)

    parts = [
        "# Pregled sto najbolj obiskanih strani", "",
        f"Nabor: {read_json(root / 'domene.json').get('source') or '-'}, "
        f"{len(targets)} domen, od tega {reachable} dosegljivih.",
        f"Izhodisce je postavitev {BASE} (brez stikala in posrednika), merjena postavitev "
        f"je {MEASURED}.", "",
        "## Delovanje strani", "",
        f"Imenovalec je stevilo strani, ki delujejo ze v {BASE}; stran, ki ne dela niti "
        "brez", "prestrezanja, v odstotek ne steje.", "",
        main_table(matrix), "",
        "## Pokritost nabora", "",
        coverage_table(matrix, reachable), "",
        "## Razlogi", "",
        reasons_table(matrix, "broken",
                      f"Zakaj stran, ki dela v {BASE}, ne dela v {MEASURED}:"), "",
        reasons_table(matrix, "base_fail",
                      f"Zakaj stran ne dela ze v {BASE}, torej brez prestrezanja:"), "",
        "## Razsodbe stikala", "",
        switch_table(root, matrix), "",
    ]
    (root / "results.md").write_text("\n".join(parts), encoding="utf-8")
    (root / "nedelujoce.md").write_text(broken_report(root, matrix), encoding="utf-8")
    (root / "results.json").write_text(json.dumps({
        "source": read_json(root / "domene.json"),
        "reachable": reachable,
        "cells": {f"{client}/{proto}": {
            "probed": cell["probed"], "base_ok": cell["base_ok"],
            "measured_ok": cell["measured_ok"],
            "broken": [item.get("domain") for item in cell["broken"]],
            "recovered": [item.get("domain") for item in cell["recovered"]],
        } for (client, proto), cell in sorted(matrix.items())},
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    for (client, proto), cell in sorted(matrix.items()):
        print(f"  {client} {PROTO_LABELS.get(proto, proto)}: "
              f"{cell['measured_ok']} od {cell['base_ok']} "
              f"({pct(cell['measured_ok'], cell['base_ok'])}), "
              f"ne dela {len(cell['broken'])}")
    print(f"  {root / 'results.md'}, nedelujoce.md, results.json")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    root = Path(argv[0]) if argv else OKOLJE / "out" / "splet"
    if not root.is_dir():
        raise SystemExit(f"splet_report: imenika '{root}' ni")
    return report(root)


if __name__ == "__main__":
    raise SystemExit(main())
