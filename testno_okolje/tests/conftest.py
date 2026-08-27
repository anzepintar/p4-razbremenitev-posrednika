from __future__ import annotations

import itertools
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
OKOLJE = ROOT / "okolje"

sys.path.insert(0, str(ROOT / "orodja"))
sys.path.insert(0, str(OKOLJE))
sys.path.insert(0, str(OKOLJE / "client"))

from runner.curlrun import PROTO_FLAG

TOPO = "B0"
CLIENT = f"clab-{TOPO}-client"
SWITCH = f"clab-{TOPO}-switch"
MITM = f"clab-{TOPO}-mitm"
SERVER_IP = "10.0.2.10"
CACERT = "/opt/traffic/pki/trust.pem"


def pytest_collection_modifyitems(items):
    for item in items:
        for level in ("unit", "integration", "e2e"):
            if f"/tests/{level}/" in str(item.fspath).replace("\\", "/"):
                item.add_marker(level)


def docker(node: str, *argv: str, check: bool = True, timeout: int = 60, detach: bool = False):
    flags = ["-d"] if detach else []
    return subprocess.run(
        ["docker", "exec", *flags, node, *argv],
        capture_output=True, text=True, check=check, timeout=timeout,
    )


def node_running(node: str) -> bool:
    if shutil.which("docker") is None:
        return False
    out = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True
    )
    return node in out.stdout.split()


def dataplane_up() -> bool:
    if not all(node_running(n) for n in (CLIENT, SWITCH, MITM)):
        return False
    try:
        links = docker(SWITCH, "ip", "-br", "link", check=False, timeout=15).stdout
        procs = docker(SWITCH, "sh", "-c", "ps ax", check=False, timeout=15).stdout
    except (subprocess.SubprocessError, OSError):
        return False
    return "eth3" in links and "simple_switch" in procs


def proxy_up() -> bool:
    try:
        ports = docker(MITM, "ss", "-lntu", check=False, timeout=15).stdout
    except (subprocess.SubprocessError, OSError):
        return False
    return ":8080" in ports


@pytest.fixture(scope="session")
def lab():
    if not dataplane_up():
        pytest.skip(f"postavitev {TOPO} ne tece; zazeni ./orodja/start.sh {TOPO}")
    if not proxy_up():
        pytest.skip(
            f"posrednik v {TOPO} ne poslusa na 8080; poglej okolje/out/mitm.log "
            "- najbrz se mitmdump ni zagnal"
        )
    return TOPO


P4 = OKOLJE / "switch" / "usmerjanje.p4"


def p4_const(name: str) -> int:
    """Konstanta iz usmerjanje.p4. Testi jo berejo iz izvorne kode, da se meje
    razclenjevalnika in test ne moreta razhajati."""
    found = re.search(rf"const\s+bit<\d+>\s+{name}\s*=\s*(\d+)",
                      P4.read_text(encoding="utf-8"))
    assert found, f"konstante {name} ni v usmerjanje.p4"
    return int(found.group(1))


SIZE = 100_000


def metric_rows(count: int, *, duration: float, group: str = "unknown",
                expect_blocked: bool = False, failures: int = 0,
                size: int = SIZE) -> list[dict]:
    """Vrstice metrik za lazno celico. Neuspesne so prve, ker jih obe merili
    stejeta po delezu in ne po vrstnem redu."""
    rows = []
    for index in range(count):
        failed = index < failures
        rows.append({
            "ts": 1000.0 + index * (duration / max(count, 1)),
            "url": "https://x.example/index.html",
            "group": group,
            "expect_blocked": expect_blocked,
            "exitcode": 28 if failed else 0,
            "time_appconnect": None if failed else 0.02,
            "time_total": 0.05,
            "size_download": 0 if failed else size,
        })
    return rows


def write_cell(directory: Path, rows: list[dict], **meta) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "metrics.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    (directory / "meta.json").write_text(json.dumps(meta), encoding="utf-8")


TESTSET = OKOLJE / "server" / "testset"


def testset_domains(subset: str = "testni") -> set[str]:
    root = TESTSET / subset
    if not root.is_dir():
        return set()
    return {p.name for p in root.iterdir() if p.is_dir()}


def listed_domains() -> dict[str, list[str]]:
    import sni

    return sni.load("domain", OKOLJE / "lists")


def groups() -> dict[str, list[str]]:
    import experiment as exp

    try:
        return exp.by_group(exp.read_assignment(OKOLJE / "lists" / "assignment.json"))
    except exp.ExperimentError as error:
        pytest.skip(str(error))


def in_group(group: str) -> str:
    present = testset_domains()
    for domain in groups().get(group, []):
        if domain in present:
            return domain
    pytest.skip(f"v naboru ni domene iz skupine '{group}'")


@pytest.fixture(scope="session")
def benign():
    return in_group("unknown")


def curl(domain: str, proto: str = "h2", *, path: str = "/index.html", timeout: int = 15):
    argv = [
        "curl", "--silent", "--output", "/dev/null", *PROTO_FLAG[proto],
        "--max-time", str(timeout), "--cacert", CACERT,
        "--resolve", f"{domain}:443:{SERVER_IP}",
        "--write-out", "%{json}",
        f"https://{domain}{path}",
    ]
    done = docker(CLIENT, *argv, check=False, timeout=timeout + 15)
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError:
        return {"exitcode": -1, "stderr": done.stderr}


def cert_issuer(domain: str, proto: str = "h2", timeout: int = 15) -> str:
    argv = [
        "curl", "-sv", *PROTO_FLAG[proto], "--max-time", str(timeout),
        "--cacert", CACERT, "--resolve", f"{domain}:443:{SERVER_IP}",
        "-o", "/dev/null", f"https://{domain}/index.html",
    ]
    done = docker(CLIENT, *argv, check=False, timeout=timeout + 15)
    for line in done.stderr.splitlines():
        if line.startswith("*  issuer:"):
            return line.split("issuer:", 1)[1].strip()
    return ""


def flow_count(domain: str) -> int:
    out = docker(
        MITM, "sh", "-c",
        f"grep -c '\"{domain}\"' /opt/traffic/out/proxy_flows.jsonl 2>/dev/null || true",
        check=False, timeout=30,
    ).stdout
    return int(out.strip() or 0)


def counters() -> dict[str, int]:
    out = "/opt/traffic/out/test_stats.json"
    docker(MITM, "/opt/p4venv/bin/python", "/opt/traffic/proxy/steer.py", "--stats", out, timeout=90)
    return json.loads(docker(MITM, "cat", out, timeout=15).stdout)


_capture_seq = itertools.count()


def capture(iface: str, count: int, expr: str, seconds: int = 20) -> str:
    dump = f"/tmp/cap_{iface}_{next(_capture_seq)}_{int(time.time())}.txt"
    docker(
        SWITCH, "sh", "-c",
        f"exec timeout {seconds} tcpdump -l -i {iface} -nn -c {count} '{expr}' >{dump} 2>&1",
        detach=True, timeout=15,
    )
    for _ in range(40):
        text = docker(SWITCH, "cat", dump, check=False, timeout=10).stdout
        if "listening on" in text:
            return dump
        time.sleep(0.25)
    raise RuntimeError(f"tcpdump na {iface} se ni zagnal")


def capture_read(dump: str) -> list[str]:
    text = docker(SWITCH, "cat", dump, check=False, timeout=15).stdout
    return [line for line in text.splitlines() if " IP " in line]


def strategy_of_proxy() -> str:
    script = (
        "for p in /proc/[0-9]*/cmdline; do tr '\\0' ' ' <\"$p\" 2>/dev/null; echo; done"
    )
    out = docker(MITM, "sh", "-c", script, check=False, timeout=20).stdout
    line = next((l for l in out.splitlines() if "mitmdump" in l or "mitmweb" in l), "")
    return "lazy" if "connection_strategy=lazy" in line else "eager"
