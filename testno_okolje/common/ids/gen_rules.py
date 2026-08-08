#!/usr/bin/env python3
"""Iz testnega nabora naredi ids/testset.rules"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent
sys.path.insert(0, str(COMMON / "client"))

from runner import scenario as scenario_mod  # noqa: E402

SID_BASE = 1000000

HEADER = """# Nastalo iz {manifest} - ne urejaj rocno, popravi gen_rules.py.
# {count} phishing domen iz nabora '{name}'.
"""

RULE = (
    'alert tls any any -> any any (msg:"phishing SNI {domain}"; '
    "tls.sni; content:\"{domain}\"; bsize:{size}; "
    "sid:{sid}; rev:1;)"
)


def render(scenario: scenario_mod.Scenario) -> str:
    sites = scenario.by_label("mal")
    lines = [
        HEADER.format(
            manifest=f"testset/{scenario.run.subset}/sites.json",
            count=len(sites),
            name=scenario.run.subset,
        )
    ]
    for index, site in enumerate(sites):
        lines.append(
            RULE.format(domain=site.domain, size=len(site.domain), sid=SID_BASE + index)
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=COMMON / "scenario.yml")
    parser.add_argument("--testset", default=COMMON / "server" / "testset")
    parser.add_argument("-o", "--out", default=HERE / "testset.rules")
    args = parser.parse_args(argv)

    scenario = scenario_mod.load(args.config, testset=args.testset)
    Path(args.out).write_text(render(scenario), encoding="utf-8")
    print(f"{args.out}: {len(scenario.by_label('mal'))} pravil")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
