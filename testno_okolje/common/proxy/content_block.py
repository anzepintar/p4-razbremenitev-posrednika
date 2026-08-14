#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from mitmproxy import ctx, flowfilter, http

RULES = Path(os.environ.get("RULES", "/opt/traffic/lists/content_rules.txt"))
THRESHOLD = int(os.environ.get("BLOCK_THRESHOLD", "100"))

BLOCK_PAGE = b"""<!doctype html>
<html lang="sl"><head><meta charset="utf-8"><title>Blokirano</title></head>
<body><h1>Stran je blokirana</h1>
<p>Posrednik je v vsebini strani prepoznal phishing.</p></body></html>
"""


class RuleError(ValueError):
    pass


def load_rules(path: Path) -> list[tuple[int, str, flowfilter.TFilter]]:
    if not path.is_file():
        raise RuleError(f"{path}: pravilnika ni")

    rules = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            weight, name, pattern = line.split(maxsplit=2)
            rules.append((int(weight), name, flowfilter.parse(pattern)))
        except ValueError as error:
            raise RuleError(f"{path}:{number}: {error}\n    {line}") from error

    if not rules:
        raise RuleError(f"{path}: datoteka nima nobenega pravila")
    return rules


class ContentBlock:
    def __init__(self) -> None:
        self.rules: list[tuple[int, str, flowfilter.TFilter]] = []
        self.error: str | None = None
        try:
            self.rules = load_rules(RULES)
        except (RuleError, OSError) as error:
            self.error = str(error)

    def running(self) -> None:
        if self.error is not None:
            logging.error("content_block: %s", self.error)
            logging.error("content_block: brez pravilnika ne blokiram nicesar, koncujem")
            ctx.master.shutdown()
            return

        logging.info("content_block: %d pravil iz %s, prag %d",
                     len(self.rules), RULES, THRESHOLD)
        for weight, name, match in self.rules:
            logging.info("content_block:   %4d %-20s %s", weight, name, match)

    def response(self, flow: http.HTTPFlow) -> None:
        if not self.rules or flow.response is None:
            return

        matched = [(weight, name) for weight, name, match in self.rules if match(flow)]
        if sum(weight for weight, _ in matched) < THRESHOLD:
            return

        flow.response = http.Response.make(
            403,
            BLOCK_PAGE,
            {
                "Content-Type": "text/html; charset=utf-8",
                # Enaki glavi kot Caddyjevi, da runner vrstico pripise pravi domeni.
                "X-Domain": flow.request.host_header or flow.request.pretty_host,
                "X-Sni": getattr(flow.client_conn, "sni", None) or "",
                "X-Block": ",".join(name for _, name in matched),
            },
        )


addons = [ContentBlock()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="content_block")
    parser.add_argument("rules", nargs="?", default=RULES, type=Path)
    args = parser.parse_args(argv)

    try:
        rules = load_rules(args.rules)
    except (RuleError, OSError) as error:
        print(f"content_block: {error}", file=sys.stderr)
        return 1

    print(f"{args.rules}: {len(rules)} pravil, prag {THRESHOLD}")
    for weight, name, match in rules:
        print(f"  {weight:>4}  {name:<20}  {match}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
