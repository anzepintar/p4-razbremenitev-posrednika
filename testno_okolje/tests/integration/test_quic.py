from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import plot

ROOT = Path(__file__).resolve().parents[2]
P4 = ROOT / "okolje" / "switch" / "steering.p4"
VECTORS = ROOT / "tests" / "data" / "quic_initials.json"
IMAGE = "p4-switch:latest"
SELFTEST = "/opt/switch/lib/quic_selftest"


def steer_module():
    spec = importlib.util.spec_from_file_location(
        "steer", ROOT / "okolje" / "proxy" / "steer.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def p4_counters() -> list[str]:
    text = P4.read_text(encoding="utf-8")
    found = re.findall(r"const\s+bit<32>\s+STAT_(\w+)\s*=\s*(\d+)", text)
    return [name.lower() for name, _ in sorted(found, key=lambda item: int(item[1]))]


def p4_const(name: str) -> int:
    found = re.search(rf"const\s+bit<\d+>\s+{name}\s*=\s*(\d+)", P4.read_text(encoding="utf-8"))
    assert found, f"konstante {name} ni v steering.p4"
    return int(found.group(1))


def selftest_present() -> bool:
    if shutil.which("docker") is None:
        return False
    done = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "test", IMAGE, "-x", SELFTEST],
        capture_output=True, text=True,
    )
    return done.returncode == 0


def run_selftest(lines: list[str], max_name: int | None = None) -> list[str]:
    argv = ["docker", "run", "--rm", "-i", IMAGE, SELFTEST]
    if max_name is not None:
        argv.append(str(max_name))
    done = subprocess.run(
        argv, input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=120
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.split()[0::3], done.stdout.splitlines()


@pytest.fixture(scope="module")
def vectors() -> dict:
    if not VECTORS.is_file():
        pytest.skip(f"vektorjev ni v {VECTORS}")
    return json.loads(VECTORS.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def selftest():
    if not selftest_present():
        pytest.skip(f"{SELFTEST} ni v sliki {IMAGE}; pozeni ./orodja/build.sh")
    return run_selftest


class TestStevci:

    def test_imena_v_steer_ustrezajo_programu(self):
        assert list(steer_module().STATS) == p4_counters()

    def test_imena_v_plot_ustrezajo_programu(self):
        assert list(plot.SWITCH_KEYS) == p4_counters()

    def test_velikost_polja_pokriva_vse_stevce(self):
        text = P4.read_text(encoding="utf-8")
        found = re.search(r"counter\((\d+),", text)
        assert found and int(found.group(1)) == len(p4_counters())


class TestRazclenitev:

    def test_vsak_vektor_da_pricakovano_ime(self, selftest, vectors):
        lines = []
        expected = []
        for index, (name, case) in enumerate(sorted(vectors.items())):
            lines += [f"{index} {hexed}" for hexed in case["datagrams"]]
            expected.append((name, case["sni"] or "-"))

        _, rows = selftest(lines)
        seen = {}
        at = 0
        for index, (name, case) in enumerate(sorted(vectors.items())):
            last = rows[at + len(case["datagrams"]) - 1]
            at += len(case["datagrams"])
            seen[name] = last.split()[1]
        assert seen == dict(expected)

    def test_razdeljen_hello_se_sestavi_sele_v_drugem_datagramu(self, selftest, vectors):
        case = vectors["razdeljen"]
        _, rows = selftest([f"1 {hexed}" for hexed in case["datagrams"]])
        assert rows[0].split()[1] == "-"
        assert rows[1].split()[1] == case["sni"]
        assert rows[1].split()[0] == "fresh"

    def test_curlov_razdeljen_hello_da_ime_ze_v_prvem_datagramu(self, selftest, vectors):
        case = vectors["posnet_curl_razdeljen"]
        assert len(case["datagrams"]) == 2
        _, rows = selftest([f"1 {case['datagrams'][0]}"])
        assert rows[0].split()[1] == case["sni"], (
            "curl posilja ClientHello v dveh datagramih; ime je v prvem in razsodba "
            "mora pasti takoj, sicer se tok pripne na posrednika"
        )

    def test_ponovljen_datagram_pride_iz_predpomnilnika(self, selftest, vectors):
        hexed = vectors["aioquic"]["datagrams"][0]
        _, rows = selftest([f"1 {hexed}", f"1 {hexed}"])
        assert [row.split()[0] for row in rows] == ["fresh", "cached"]
        assert {row.split()[1] for row in rows} == {vectors["aioquic"]["sni"]}

    def test_locena_toka_se_ne_mesata(self, selftest, vectors):
        first = vectors["aioquic"]["datagrams"][0]
        second = vectors["razdeljen"]["datagrams"][0]
        _, rows = selftest([f"1 {first}", f"2 {second}"])
        assert rows[0].split()[1] == vectors["aioquic"]["sni"]
        assert rows[1].split()[1] == "-"

    def test_ime_cez_mejo_odpade(self, selftest, vectors):
        case = vectors["aioquic_long"]
        assert len(case["sni"]) == p4_const("MAX_SNI_NAME")
        _, rows = selftest([f"1 {case['datagrams'][0]}"], max_name=len(case["sni"]) - 1)
        assert rows[0].split()[1] == "-"

    def test_smeti_ne_dajo_imena(self, selftest, vectors):
        _, rows = selftest([f"1 {vectors['smeti']['datagrams'][0]}"])
        assert rows[0].split()[1] == "-"
