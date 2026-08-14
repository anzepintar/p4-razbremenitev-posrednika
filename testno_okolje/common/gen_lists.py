#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "client"))

import sni
from runner import scenario as scenario_mod

TESTSET = HERE / "server" / "testset"
EXTRA_BLACK = ["24ur.com"]
EXTRA_WHITE = ["anzepintar.com", "quic.anzepintar.com"]

HEADERS = {
    ("domain", "black"): [
        "Domene, ki jih stikalo zavrze ob ClientHello, posrednik pa v prometu QUIC.",
        "Ena na vrstico, # je opomba, zacetna pika velja za vse poddomene (.primer.com).",
    ],
    ("domain", "white"): [
        "Domene, ki jih posrednik le tunelira - brez desifriranja in brez potrdila.",
        "Ena na vrstico, # je opomba, zacetna pika velja za vse poddomene (.primer.com).",
    ],
    ("ip", "black"): [
        "Naslovi, ki jih stikalo zavrze ze ob paketu SYN.",
        "Naslov, predpona CIDR ali domena (razresi se ob zagonu), ena na vrstico.",
    ],
    ("ip", "white"): [
        "Naslovi, ki gredo mimo posrednika naravnost na streznik oziroma v splet.",
        "Naslov, predpona CIDR ali domena (razresi se ob zagonu), ena na vrstico.",
    ],
}


def sample(domains: list[str], share: float) -> list[str]:
    if not 0.0 <= share <= 1.0:
        raise SystemExit(f"gen_lists.py: share {share} ni med 0 in 1")
    ranked = sorted(domains, key=lambda d: hashlib.sha1(d.encode()).hexdigest())
    return ranked[: round(len(domains) * share)]


def render(kind: str, name: str, items: list[str]) -> str:
    lines = [f"# {line}" for line in HEADERS[(kind, name)]]
    return "\n".join(lines + [""] + sorted(set(items))) + "\n"


def write(kind: str, name: str, items: list[str], force: bool) -> str:
    target = sni.path(kind, name)
    if target.exists() and not force:
        return f"{target.name}: {len(sni.read(target))} postavk (obstaja, ni spremenjen)"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render(kind, name, items), encoding="utf-8")
    return f"{target.name}: {len(set(items))} postavk (zapisano)"


def report(black: list[str]) -> None:
    try:
        scenario = scenario_mod.load(HERE / "scenario.yml", testset=TESTSET)
    except (scenario_mod.ScenarioError, FileNotFoundError, KeyError):
        return
    mal = {site.domain for site in scenario.by_label("mal")}
    listed = set(black)
    missing = mal - listed
    outside = {d for d in listed - set(scenario.sites) if not d.startswith(".")}
    print(f"nabor '{scenario.run.subset}': {len(mal - missing)} od {len(mal)} domen 'mal' "
          f"je na crnem seznamu, {len(outside)} postavk ni v naboru")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gen_lists")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--white-share", type=float, default=0.0)
    parser.add_argument("--black-share", type=float, default=1.0)
    args = parser.parse_args(argv)

    try:
        scenario = scenario_mod.load(HERE / "scenario.yml", testset=TESTSET)
        mal = [site.domain for site in scenario.by_label("mal")]
        ben = [site.domain for site in scenario.by_label("ben")]
    except (scenario_mod.ScenarioError, FileNotFoundError, KeyError) as error:
        print(f"gen_lists.py: nabora ni mogoce prebrati ({error}), seznami bodo prazni")
        mal, ben = [], []

    seeds = {
        ("domain", "black"): sample(mal, args.black_share) + EXTRA_BLACK,
        ("domain", "white"): sample(ben, args.white_share) + EXTRA_WHITE,
        ("ip", "black"): [],
        ("ip", "white"): [],
    }
    for (kind, name), items in seeds.items():
        print(write(kind, name, items, args.force))

    report(sni.load("domain")["black"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
