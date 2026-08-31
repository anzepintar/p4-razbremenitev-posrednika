from __future__ import annotations

import json
import time

import pytest

from conftest import (
    CLIENT, MITM, PROTO_FLAG, SERVER_IP, capture, capture_read, cert_issuer,
    counters, curl, docker, flow_count, in_group,
)


def pick(name: str) -> str:
    return in_group({"black": "sni_black", "white": "sni_white"}[name])


def proxy_flows() -> list[dict]:
    out = docker(MITM, "cat", "/opt/traffic/out/proxy_flows.jsonl", check=False).stdout
    return [json.loads(line) for line in out.splitlines() if line.strip()]


class TestPrivzetaPot:

    def test_zahteva_h2_uspe(self, lab, benign):
        result = curl(benign, "h2")
        assert result["http_code"] == 200
        assert str(result["http_version"]) == "2"

    def test_zahteva_h3_uspe(self, lab, benign):
        result = curl(benign, "h3")
        assert result["http_code"] == 200
        assert str(result["http_version"]) == "3"

    def test_streznik_vidi_pravi_sni(self, lab, benign):
        argv = [
            "curl", "-s", "-o", "/dev/null", *PROTO_FLAG["h2"], "--max-time", "15",
            "--cacert", "/opt/traffic/pki/trust.pem",
            "--resolve", f"{benign}:443:{SERVER_IP}",
            "--write-out", '%header{x-sni}|%header{x-domain}',
            f"https://{benign}/index.html",
        ]
        out = docker(CLIENT, *argv, check=False).stdout
        assert out == f"{benign}|{benign}"

    def test_potrdilo_izda_posrednik(self, lab, benign):
        issuer = cert_issuer(benign)
        assert "mitmproxy" in issuer, f"seja ni bila desifrirana: {issuer}"

    def test_seja_je_zabelezena_pri_posredniku(self, lab, benign):
        curl(benign, "h2")
        time.sleep(1)
        hosts = {flow.get("host") or flow.get("pretty_host") for flow in proxy_flows()}
        assert benign in hosts


class TestBelaDomena:

    def test_zahteva_uspe(self, lab):
        domain = pick("white")
        assert curl(domain, "h2")["http_code"] == 200

    def test_potrdilo_je_strezniško(self, lab):
        domain = pick("white")
        issuer = cert_issuer(domain)
        assert issuer, "izdajatelja ni bilo mogoce prebrati"
        assert "mitmproxy" not in issuer, f"bela domena je bila desifrirana: {issuer}"

    def test_posrednik_seje_ne_zabelezi(self, lab):
        domain = pick("white")
        before = flow_count(domain)
        assert curl(domain, "h2")["http_code"] == 200
        time.sleep(2)
        assert flow_count(domain) == before


def quiet_counters(settle: float = 3.0, tries: int = 10) -> dict[str, int]:
    previous = counters()
    for _ in range(tries):
        time.sleep(settle)
        current = counters()
        if current == previous:
            return current
        previous = current
    return previous


class TestStevci:

    def test_ena_zahteva_h2_da_en_sni_seen(self, lab, benign):
        before = quiet_counters()
        curl(benign, "h2")
        after = counters()
        assert after["sni_seen"] - before["sni_seen"] == 1

    def test_zahteva_h3_ne_da_sni_seen(self, lab, benign):
        window = 8
        idle_before = counters()
        time.sleep(window)
        idle_after = counters()
        noise = idle_after["sni_seen"] - idle_before["sni_seen"]

        before = counters()
        curl(benign, "h3", timeout=window)
        after = counters()
        assert after["quic"] > before["quic"], "odhodni QUIC mora biti presteti"
        assert after["sni_seen"] - before["sni_seen"] <= noise, (
            "zahteva h3 ne sme prispevati k sni_seen"
        )


class TestQuicRazsodba:

    def test_zahteva_h3_da_quic_sni(self, lab, benign):
        before = quiet_counters()
        curl(benign, "h3", timeout=8)
        after = counters()
        assert after["quic_sni"] - before["quic_sni"] == 1, (
            "stikalo mora iz zacetnega paketa QUIC prebrati natanko eno ime"
        )

    def test_neznana_domena_gre_prek_posrednika(self, lab, benign):
        before = quiet_counters()
        curl(benign, "h3", timeout=8)
        after = counters()
        assert after["quic"] > before["quic"]
        assert after["quic_white"] == before["quic_white"]


class TestQuicBelaDomena:

    def test_zahteva_uspe(self, lab):
        assert curl(pick("white"), "h3")["http_code"] == 200

    def test_potrdilo_je_strezniško(self, lab):
        issuer = cert_issuer(pick("white"), "h3")
        assert issuer, "izdajatelja ni bilo mogoce prebrati"
        assert "mitmproxy" not in issuer, f"bela domena h3 je bila desifrirana: {issuer}"

    def test_stikalo_tok_spelje_mimo_posrednika(self, lab):
        domain = pick("white")
        before = quiet_counters()
        assert curl(domain, "h3")["http_code"] == 200
        after = counters()
        assert after["quic_white"] > before["quic_white"]
        assert after["quic"] == before["quic"], (
            "beli tok QUIC ne sme dobiti nobenega paketa prek posrednika"
        )

    def test_posrednik_seje_ne_zabelezi(self, lab):
        domain = pick("white")
        before = flow_count(domain)
        assert curl(domain, "h3")["http_code"] == 200
        time.sleep(2)
        assert flow_count(domain) == before


class TestPovratniQuic:

    def test_stikalo_steje_odhodni_quic(self, lab, benign):
        before = quiet_counters()
        curl(benign, "h3", timeout=8)
        after = counters()
        assert after["quic"] > before["quic"], "odhodni QUIC do posrednika mora biti presteti"

    def test_povratni_quic_ni_zavrnjen(self, lab, benign):
        idle_before = counters()
        time.sleep(8)
        idle_after = counters()
        noise = idle_after["denied"] - idle_before["denied"]

        before = counters()
        curl(benign, "h3", timeout=8)
        after = counters()
        assert after["denied"] - before["denied"] <= noise, (
            "povratni QUIC se zavraca - preveri pogoj srcPort v krmiljenje.p4"
        )

    def test_datagrami_pridejo_do_odjemalca(self, lab, benign):
        to_client = capture("eth1", 4, "udp and src host 10.0.2.10", seconds=20)
        to_proxy = capture("eth3", 4, "udp and src host 10.0.2.10", seconds=20)
        curl(benign, "h3", timeout=8)
        time.sleep(4)
        assert capture_read(to_proxy), "posrednik mora odgovoriti"
        assert capture_read(to_client), "stikalo mora odgovor prepustiti odjemalcu"


class TestQuicPregled:

    def test_odjemalec_dobi_potrdilo_posrednika(self, lab, benign):
        issuer = cert_issuer(benign, "h3")
        assert "mitmproxy" in issuer, f"h3 ni bil desifriran: {issuer!r}"

    def test_seja_h3_je_zabelezena(self, lab, benign):
        before = flow_count(benign)
        assert curl(benign, "h3")["http_code"] == 200
        time.sleep(2)
        assert flow_count(benign) > before, "seje h3 ni v proxy_flows.jsonl"

    def test_streznik_vidi_pravi_sni_tudi_pri_h3(self, lab, benign):
        argv = [
            "curl", "-s", "-o", "/dev/null", *PROTO_FLAG["h3"], "--max-time", "15",
            "--cacert", "/opt/traffic/pki/trust.pem",
            "--resolve", f"{benign}:443:{SERVER_IP}",
            "--write-out", "%header{x-sni}|%header{x-domain}",
            f"https://{benign}/index.html",
        ]
        out = docker(CLIENT, *argv, check=False).stdout
        assert out == f"{benign}|{benign}"


# Crna domena se pri obeh prenosih obnasa enako, le stevec je drug. Bela domena
# je nasprotno nesimetricna, ker jo pri TCP posrednik tunelira, pri QUIC pa jo
# stikalo spelje mimo njega, zato tam razreda ostaneta locena.
@pytest.mark.parametrize("proto,counter",
                         [("h2", "sni_blocked"), ("h3", "quic_blocked")],
                         ids=["h2", "h3"])
class TestCrnaDomena:

    def test_zahteva_ne_uspe(self, lab, proto, counter):
        domain = pick("black")
        result = curl(domain, proto, timeout=8)
        assert result.get("http_code") in (0, None) or result.get("exitcode", 0) != 0

    def test_stevec_na_stikalu_naraste(self, lab, proto, counter):
        domain = pick("black")
        before = counters()
        curl(domain, proto, timeout=8)
        after = counters()
        assert after[counter] > before[counter]

    def test_posrednik_seje_ne_zabelezi(self, lab, proto, counter):
        domain = pick("black")
        curl(domain, proto, timeout=8)
        time.sleep(1)
        hosts = {flow.get("host") or flow.get("pretty_host") for flow in proxy_flows()}
        assert domain not in hosts
