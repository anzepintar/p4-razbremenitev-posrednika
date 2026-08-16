from __future__ import annotations

import random
import re
import time

import pytest

from conftest import (
    capture, capture_read, curl, listed_domains, strategy_of_proxy, testset_domains,
)

CLIENT_IP = "10.0.1.10"
PROXY_IP = "10.0.3.10"

_used: set[str] = set()


@pytest.fixture(scope="module")
def strategy(lab) -> str:
    return strategy_of_proxy()


@pytest.fixture
def fresh_domain():
    lists = listed_domains()
    marked = {d.lstrip(".") for d in lists["black"] + lists["white"]}
    pool = sorted(testset_domains() - marked - _used)
    if not pool:
        pytest.skip("ni vec nezahtevanih domen")
    domain = random.choice(pool)
    _used.add(domain)
    return domain


def classify(line: str) -> str | None:
    source = line.split(">")[0]
    if PROXY_IP in source and "Flags [S]" in line:
        return "upstream_syn"
    if CLIENT_IP in source and "Flags [P." in line:
        length = re.search(r"length (\d+)", line)
        if length and int(length.group(1)) > 500:
            return "client_hello"
    return None


def timeline(domain: str, timeout: int = 12) -> list[str]:
    dump = capture("eth3", 40, "tcp port 443", seconds=timeout + 10)
    curl(domain, "h2", timeout=timeout)
    time.sleep(4)

    events = []
    for line in capture_read(dump):
        kind = classify(line)
        if kind and (not events or events[-1] != kind):
            events.append(kind)
    return events


class TestVrstniRed:
    def test_strategija_je_prepoznana(self, strategy):
        assert strategy in ("eager", "lazy")

    def test_vrstni_red_ustreza_strategiji(self, lab, strategy, fresh_domain):
        events = timeline(fresh_domain)
        assert "client_hello" in events, f"odjemalcev ClientHello ni bil zajet: {events}"
        assert "upstream_syn" in events, f"zgornja povezava se ni odprla: {events}"

        first_syn = events.index("upstream_syn")
        first_hello = events.index("client_hello")
        if strategy == "eager":
            assert first_syn < first_hello, f"eager odpre navzgor pred ClientHello: {events}"
        else:
            assert first_hello < first_syn, f"lazy pocaka na ClientHello: {events}"


class TestRazbremenitev:

    def test_crna_domena_in_povezava_navzgor(self, lab, strategy):
        from test_poti import pick

        domain = pick("black")
        events = timeline(domain, timeout=8)
        opened = "upstream_syn" in events

        if strategy == "eager":
            assert opened, (
                "pri eager posrednik odpre povezavo navzgor, ceprav stikalo sejo zavrze - "
                "razbremenitev je zato le delna"
            )
        else:
            assert not opened, (
                "pri lazy posrednik povezave navzgor ne sme odpreti, ker ClientHello nikoli "
                "ne pride - razbremenitev je polna"
            )
