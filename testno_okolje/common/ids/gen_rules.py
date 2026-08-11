#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent
sys.path.insert(0, str(COMMON / "client"))

from runner import scenario as scenario_mod

TESTSET = COMMON / "server" / "testset"
OUT = HERE / "testset.rules"
SID_BASE = 1000000

HEADER = "# Nastalo iz {manifest} - ne urejaj rocno, popravi gen_rules.py.\n"

RULE = (
    'alert tls any any -> any any (msg:"phishing SNI {domain}"; '
    "tls.sni; content:\"{domain}\"; bsize:{size}; "
    "sid:{sid}; rev:1;)"
)


def render(scenario: scenario_mod.Scenario) -> str:
    sites = scenario.by_label("mal")
    lines = [HEADER.format(manifest=f"testset/{scenario.run.subset}/sites.json")]
    for index, site in enumerate(sites):
        lines.append(RULE.format(domain=site.domain, size=len(site.domain), sid=SID_BASE + index))
    return "\n".join(lines) + "\n"


def main() -> int:
    scenario = scenario_mod.load(COMMON / "scenario.yml", testset=TESTSET)
    OUT.write_text(render(scenario), encoding="utf-8")
    print(f"{OUT}: {len(scenario.by_label('mal'))} pravil")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
