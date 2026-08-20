#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OKOLJE = HERE.parent / "okolje"
sys.path.insert(0, str(OKOLJE))
sys.path.insert(0, str(OKOLJE / "client"))

from runner import scenario as scenario_mod

TESTSET = OKOLJE / "server" / "testset"
ROOT = "/opt/traffic/server/testset"
OUT = OKOLJE / "server" / "sites.caddy"

HEADER = """# Nastalo iz {manifest} - ne urejaj rocno, popravi gen_caddyfile.py.

(site) {{
	tls internal

	header X-Domain {{host}}
	header X-Sni {{http.request.tls.server_name}}

	root * {root}/{{host}}
	try_files {{path}} /_asset.bin
	file_server
}}
"""

BLOCK = """
{addresses} {{
	import site
}}
"""


def render(scenario: scenario_mod.Scenario) -> str:
    text = HEADER.format(
        manifest="experiment.yml + lists/assignment.json",
        root=f"{ROOT}/{scenario.run.subset}",
    )
    addresses = ",\n".join(f"https://{domain}" for domain in scenario.domains())
    return text + BLOCK.format(addresses=addresses)


def write(
    config: Path | None = None, testset: Path | None = None
) -> scenario_mod.Scenario:
    scenario = scenario_mod.load(
        config or OKOLJE / "experiment.yml", testset=testset or TESTSET
    )
    OUT.write_text(render(scenario), encoding="utf-8")
    return scenario


def main() -> int:
    scenario = write()
    ips = sorted({site.ip for site in scenario.sites.values()})
    print(f"{OUT}: {len(scenario.sites)} domen na naslovih {', '.join(ips)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
