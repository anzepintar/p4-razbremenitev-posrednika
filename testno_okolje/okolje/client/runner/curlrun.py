from __future__ import annotations

import json
from dataclasses import dataclass

from .scenario import Scenario

PORT = 443

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
    domain: str
    path: str
    proto: str

    @property
    def url(self) -> str:
        return f"https://{self.domain}{self.path}"


def build_argv(scenario: Scenario, request: Request, *, cacert: str) -> list[str]:
    argv = ["curl", "--silent", "--no-progress-meter", "--show-error"]
    argv += ["--connect-timeout", str(scenario.run.connect_timeout_s),
             "--max-time", str(scenario.run.max_time_s)]
    argv += PROTO_FLAG[request.proto]

    argv += ["--resolve", f"{request.domain}:{PORT}:{scenario.ip_for(request.domain)}"]
    argv += ["--cacert", cacert]

    argv += ["--write-out", WRITE_OUT]
    argv += ["--output", "/dev/null", request.url]
    return argv


def parse_output(stdout: str) -> list[dict]:
    return [json.loads(line) for line in stdout.splitlines() if line.strip()]


def to_metric(record: dict, *, labels: dict) -> dict:
    curl = record.get("curl", {})
    return {
        **labels,
        "url": curl.get("url_effective"),
        "http_code": curl.get("http_code"),
        "http_version": str(curl.get("http_version") or ""),
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
