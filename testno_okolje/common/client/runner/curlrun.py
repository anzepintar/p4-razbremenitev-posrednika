from __future__ import annotations

import json
from dataclasses import dataclass

from .scenario import Scenario
from .urls import Target

PORT = 443

CONNECT_TIMEOUT = 5
MAX_TIME = 15

WRITE_OUT = (
    '{"curl":%{json},"x_sni":"%header{x-sni}",'
    '"x_domain":"%header{x-domain}","x_block":"%header{x-block}"}\\n'
)

PROTO_FLAG = {
    "h2": ["--http2"],
    "h3": ["--http3-only"],
}


@dataclass(frozen=True)
class Request:
    """En curl klic: ena stran s podviri, en protokol."""

    targets: tuple[Target, ...]
    proto: str
    host_header: str | None = None


def build_argv(
    scenario: Scenario,
    request: Request,
    *,
    src_ip: str,
    cacert: str | None = None,
    insecure: bool = False,
) -> list[str]:
    argv = ["curl", "--silent", "--no-progress-meter", "--show-error"]
    argv += ["--connect-timeout", str(CONNECT_TIMEOUT), "--max-time", str(MAX_TIME)]
    argv += PROTO_FLAG[request.proto]

    argv += ["--interface", src_ip]

    for domain in sorted({target.domain for target in request.targets}):
        argv += ["--resolve", f"{domain}:{PORT}:{scenario.sites[domain].ip}"]

    if insecure:
        argv.append("--insecure")
    elif cacert:
        argv += ["--cacert", cacert]

    if request.host_header:
        argv += ["--header", f"Host: {request.host_header}"]

    if len(request.targets) > 1:
        argv.append("--parallel")

    argv += ["--write-out", WRITE_OUT]
    for target in request.targets:
        argv += ["--output", "/dev/null", target.url]
    return argv


def parse_output(stdout: str) -> list[dict]:
    """Vsaka neprazna vrstica je en zapis."""
    return [json.loads(line) for line in stdout.splitlines() if line.strip()]


def to_metric(record: dict, *, labels: dict) -> dict:
    """curl zapis + oznake orkestratorja -> vrstica za metrics.jsonl."""
    curl = record.get("curl", {})
    return {
        **labels,
        "url": curl.get("url_effective"),
        "http_code": curl.get("http_code"),
        "http_version": curl.get("http_version"),
        "size_download": curl.get("size_download"),
        "num_connects": curl.get("num_connects"),
        "local_ip": curl.get("local_ip"),
        "remote_ip": curl.get("remote_ip"),
        "time_connect": curl.get("time_connect"),
        "time_appconnect": curl.get("time_appconnect"),
        "time_starttransfer": curl.get("time_starttransfer"),
        "time_total": curl.get("time_total"),
        "errormsg": curl.get("errormsg") or None,
        "exitcode": curl.get("exitcode"),
        "server_sni": record.get("x_sni") or None,
        "server_domain": record.get("x_domain") or None,
        "blocked": bool(record.get("x_block")),
        "block_rules": record.get("x_block") or None,
    }
