from __future__ import annotations

import pytest

from runner import curlrun
from runner.scenario import BIG, INDEX


class FakeRun:
    connect_timeout_s = 2.0
    max_time_s = 10.0
    object_kb = 0


class FakeScenario:

    ips = {"a.com": "10.0.2.10", "b.com": "10.0.2.11"}
    run = FakeRun()

    def ip_for(self, domain: str) -> str:
        return self.ips.get(domain, "10.0.2.10")


@pytest.fixture
def scenario():
    return FakeScenario()


def request_for(domain, path="/index.html", **kwargs):
    return curlrun.Request(domain=domain, path=path, **kwargs)


class TestBuildArgv:
    def test_iztek_pride_iz_nastavitve(self, scenario):
        argv = curlrun.build_argv(scenario, request_for("a.com", proto="h2"), cacert="ca.pem")
        assert argv[argv.index("--connect-timeout") + 1] == "2.0"
        assert argv[argv.index("--max-time") + 1] == "10.0"

    def test_protokol_doloci_zastavico(self, scenario):
        for proto, flag in (("h2", "--http2"), ("h3", "--http3-only")):
            argv = curlrun.build_argv(scenario, request_for("a.com", proto=proto), cacert="ca.pem")
            assert flag in argv

    def test_neznan_protokol_je_napaka(self, scenario):
        with pytest.raises(KeyError):
            curlrun.build_argv(scenario, request_for("a.com", proto="h9"), cacert="ca.pem")

    def test_domena_dobi_resolve_na_svoj_streznik(self, scenario):
        argv = curlrun.build_argv(scenario, request_for("b.com", proto="h2"), cacert="ca.pem")
        assert argv[argv.index("--resolve") + 1] == "b.com:443:10.0.2.11"

    def test_en_cilj_na_zahtevo(self, scenario):
        argv = curlrun.build_argv(scenario, request_for("a.com", proto="h2"), cacert="c")
        assert argv[-1] == "https://a.com/index.html"
        assert argv.count("--output") == 1


class TestParseOutput:
    def test_prazne_vrstice_se_preskocijo(self):
        assert curlrun.parse_output('{"a":1}\n\n{"a":2}\n') == [{"a": 1}, {"a": 2}]

    def test_prazen_izpis(self):
        assert curlrun.parse_output("") == []


class TestToMetric:
    def test_glave_streznika_se_prenesejo(self):
        record = {
            "curl": {"http_code": 200, "http_version": 2, "url_effective": "https://a.com/"},
            "x_sni": "a.com",
            "x_domain": "a.com",
            "x_block": "",
        }
        metric = curlrun.to_metric(record, labels={"client": "c1"})
        assert metric["client"] == "c1"
        assert metric["http_code"] == 200
        assert metric["server_sni"] == "a.com"
        assert metric["blocked"] is False

    def test_blokirano_se_prepozna_po_glavi(self):
        record = {"curl": {"http_code": 403}, "x_block": "phishing,obrazec"}
        metric = curlrun.to_metric(record, labels={})
        assert metric["blocked"] is True
        assert metric["block_rules"] == "phishing,obrazec"

    def test_prazne_glave_postanejo_none(self):
        metric = curlrun.to_metric({"curl": {}, "x_sni": "", "x_domain": ""}, labels={})
        assert metric["server_sni"] is None
        assert metric["server_domain"] is None


class TestCiljZahteve:

    def scenario_with(self, object_kb):
        from runner.scenario import Scenario

        class Run:
            connect_timeout_s = 0.5
            max_time_s = 60.0

        Run.object_kb = object_kb
        return Scenario(sites={}, run=Run(), quic_share=0.0)

    def test_dokument_pri_nic(self):
        assert self.scenario_with(0).object_path == INDEX

    def test_velik_objekt_ko_je_nastavljen(self):
        assert self.scenario_with(10240).object_path == BIG


class TestSkladnostZEksperimentom:
    """Ime velikega objekta stoji na dveh mestih in ju ni mogoce zdruziti.

    Odjemalec v vsebniku ima na poti samo /opt/traffic/client, zato scenario.py
    modula experiment ne more uvoziti na vrhu. Namesto tega ju vezemo s testom.
    """

    def test_ime_velikega_objekta_se_ujema(self):
        import experiment as exp

        assert BIG == "/" + exp.BIG_OBJECT
