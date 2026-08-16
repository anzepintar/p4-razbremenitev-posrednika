from __future__ import annotations

import pytest

from runner import curlrun
from runner.urls import Target


class FakeRun:
    connect_timeout_s = 2.0
    max_time_s = 10.0


class FakeScenario:

    ips = {"a.com": "10.0.2.10", "b.com": "10.0.2.11"}
    run = FakeRun()

    def ip_for(self, domain: str) -> str:
        return self.ips.get(domain, "10.0.2.10")


@pytest.fixture
def scenario():
    return FakeScenario()


def target(domain, path="/index.html"):
    return Target(domain=domain, path=path)


class TestBuildArgv:
    def test_iztek_pride_iz_nastavitve(self, scenario):
        request = curlrun.Request(targets=(target("a.com"),), proto="h2")
        argv = curlrun.build_argv(scenario, request, src_ip=None, cacert="ca.pem")
        assert argv[argv.index("--connect-timeout") + 1] == "2.0"
        assert argv[argv.index("--max-time") + 1] == "10.0"

    def test_protokol_doloci_zastavico(self, scenario):
        for proto, flag in (("h2", "--http2"), ("h3", "--http3-only")):
            request = curlrun.Request(targets=(target("a.com"),), proto=proto)
            assert flag in curlrun.build_argv(scenario, request, src_ip="10.0.1.10", cacert="ca.pem")

    def test_neznan_protokol_je_napaka(self, scenario):
        request = curlrun.Request(targets=(target("a.com"),), proto="h9")
        with pytest.raises(KeyError):
            curlrun.build_argv(scenario, request, src_ip="10.0.1.10", cacert="ca.pem")

    def test_izvorni_naslov_je_vsiljen(self, scenario):
        request = curlrun.Request(targets=(target("a.com"),), proto="h2")
        argv = curlrun.build_argv(scenario, request, src_ip="10.0.1.12", cacert="ca.pem")
        assert argv[argv.index("--interface") + 1] == "10.0.1.12"

    def test_vsaka_domena_dobi_resolve_na_streznik(self, scenario):
        request = curlrun.Request(
            targets=(target("a.com"), target("b.com"), target("a.com", "/x")), proto="h2"
        )
        argv = curlrun.build_argv(scenario, request, src_ip="10.0.1.10", cacert="ca.pem")
        resolves = [argv[i + 1] for i, a in enumerate(argv) if a == "--resolve"]
        assert sorted(resolves) == ["a.com:443:10.0.2.10", "b.com:443:10.0.2.11"]

    def test_vec_ciljev_tece_vzporedno(self, scenario):
        one = curlrun.Request(targets=(target("a.com"),), proto="h2")
        many = curlrun.Request(targets=(target("a.com"), target("b.com")), proto="h2")
        assert "--parallel" not in curlrun.build_argv(scenario, one, src_ip="1.1.1.1", cacert="c")
        assert "--parallel" in curlrun.build_argv(scenario, many, src_ip="1.1.1.1", cacert="c")

    def test_prikrivanje_domene_doda_glavo_host(self, scenario):
        request = curlrun.Request(targets=(target("a.com"),), proto="h2", host_header="krinka.com")
        argv = curlrun.build_argv(scenario, request, src_ip="10.0.1.10", cacert="ca.pem")
        assert "Host: krinka.com" in argv


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
        class Run:
            connect_timeout_s = 0.5
            max_time_s = 60.0

        class Scenario:
            run = Run()

            def ip_for(self, domain):
                return "10.0.2.10"

        Run.object_kb = object_kb
        return Scenario()

    def test_dokument_pri_nic(self):
        from runner import urls

        targets = urls.page_targets(self.scenario_with(0), "a.com")
        assert [t.path for t in targets] == ["/index.html"]

    def test_velik_objekt_ko_je_nastavljen(self):
        from runner import urls

        targets = urls.page_targets(self.scenario_with(10240), "a.com")
        assert [t.path for t in targets] == ["/big.bin"]

    def test_vedno_en_sam_cilj(self):
        from runner import urls

        for kb in (0, 1024):
            assert len(urls.page_targets(self.scenario_with(kb), "a.com")) == 1
