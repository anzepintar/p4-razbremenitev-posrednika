#!/usr/bin/env python3
"""Iz testnega nabora naredi server/sites.caddy"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "client"))

from runner import scenario as scenario_mod  # noqa: E402

HEADER = """# Nastalo iz {manifest} - ne urejaj rocno, popravi gen_caddyfile.py.
# {count} domen na {ips} naslovih, nabor '{name}'.

(site) {{
	tls internal

	header X-Domain {{host}}
	header X-Sni {{http.request.tls.server_name}}

	# {{host}} izbere korenski imenik.
	root * {root}/{{host}}
	try_files {{path}} /_asset.bin
	file_server
}}
"""

BLOCK = """
{addresses} {{
	bind {ip}
	import site
}}
"""


def render(scenario: scenario_mod.Scenario, root: str) -> str:
    grouped = scenario.domains_by_ip()
    text = HEADER.format(
        manifest=f"testset/{scenario.run.subset}/sites.json",
        count=len(scenario.sites),
        ips=len(grouped),
        name=scenario.run.subset,
        root=root.rstrip("/"),
    )
    for ip, domains in grouped.items():
        addresses = ",\n".join(f"https://{domain}" for domain in domains)
        text += BLOCK.format(addresses=addresses, ip=ip)
    return text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=HERE / "scenario.yml")
    parser.add_argument("--testset", default=HERE / "server" / "testset",
                        help="nabor na gostitelju (za branje manifesta)")
    parser.add_argument("--root", default="/opt/traffic/server/testset",
                        help="nabor, kot ga vidi streznik")
    parser.add_argument("-o", "--out", default=HERE / "server" / "sites.caddy")
    args = parser.parse_args(argv)

    scenario = scenario_mod.load(args.config, testset=args.testset)
    root = f"{str(args.root).rstrip('/')}/{scenario.run.subset}"
    Path(args.out).write_text(render(scenario, root), encoding="utf-8")

    grouped = scenario.domains_by_ip()
    print(f"{args.out}: {len(scenario.sites)} domen na {len(grouped)} naslovih")
    for ip, domains in grouped.items():
        print(f"  {ip}: {len(domains)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
