#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "client"))

from runner import scenario as scenario_mod

TESTSET = HERE / "server" / "testset"
ROOT = "/opt/traffic/server/testset"
OUT = HERE / "server" / "sites.caddy"

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
        manifest=f"testset/{scenario.run.subset}/sites.json",
        root=f"{ROOT}/{scenario.run.subset}",
    )
    addresses = ",\n".join(f"https://{domain}" for domain in scenario.domains())
    return text + BLOCK.format(addresses=addresses)


def main() -> int:
    scenario = scenario_mod.load(HERE / "scenario.yml", testset=TESTSET)
    OUT.write_text(render(scenario), encoding="utf-8")
    print(f"{OUT}: {len(scenario.sites)} domen na {scenario.server_ip}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
