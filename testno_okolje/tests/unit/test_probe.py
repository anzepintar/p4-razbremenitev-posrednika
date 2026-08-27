from __future__ import annotations

import asyncio
import json

import plot
import splet_report
from probe import verdicts
from probe.__main__ import load_targets, nabor, with_retry

CERTS = (
    "Subject:CN = cloudflare.com\n"
    "Issuer:C = US, O = Google Trust Services, CN = WE1\n"
    "Version:2\n"
)

ERROR_PAGE = (
    '<html dir="ltr" lang="en" class="offline"><head><title>microsoft.com</title></head>'
    '<body><div id="main-frame-error"><span class="error-code">'
    "ERR_INTERNET_DISCONNECTED</span></div></body></html>"
)

GOOD_PAGE = '<html><head><title>Cloudflare</title></head><body><p>zdravo</p></body></html>'


class TestCurlUkaz:
    def test_protokol_doloci_zastavico(self):
        for proto, flag in (("h2", "--http2"), ("h3", "--http3-only")):
            argv = verdicts.curl_argv("https://a.com/", proto,
                                      connect_timeout=5, max_time=20)
            assert flag in argv

    def test_pravi_splet_nima_resolve(self):
        argv = verdicts.curl_argv("https://a.com/", "h2", connect_timeout=5, max_time=20)
        assert "--resolve" not in argv
        assert argv[-1] == "https://a.com/"

    def test_preusmeritvam_sledi_le_iskanje_gostitelja(self):
        brez = verdicts.curl_argv("https://a.com/", "h2", connect_timeout=5, max_time=20)
        zsledom = verdicts.curl_argv("https://a.com/", "h2", connect_timeout=5,
                                     max_time=20, follow=True)
        assert "--location" not in brez
        assert "--location" in zsledom

    def test_svoj_ca_le_kadar_je_podan(self):
        argv = verdicts.curl_argv("https://a.com/", "h2", connect_timeout=5, max_time=20)
        assert "--cacert" not in argv
        argv = verdicts.curl_argv("https://a.com/", "h2", connect_timeout=5,
                                  max_time=20, cacert="/pot/trust.pem")
        assert argv[argv.index("--cacert") + 1] == "/pot/trust.pem"


class TestCurlIzid:
    def test_preusmeritev_je_uspeh(self):
        """Apex domene nabora skoraj vedno vrnejo 301, zato koda ni merilo."""
        izid = verdicts.curl_verdict(
            {"exitcode": 0, "http_version": "2", "http_code": 301}, "h2")
        assert izid["ok"] is True
        assert izid["protocol"] == "h2"

    def test_starejsi_protokol_ni_uspeh(self):
        izid = verdicts.curl_verdict(
            {"exitcode": 0, "http_version": "1.1", "http_code": 301}, "h2")
        assert izid["ok"] is False
        assert izid["error"] == "protokol"

    def test_napaka_povzame_curlovo_sporocilo(self):
        izid = verdicts.curl_verdict(
            {"exitcode": 28, "http_version": "0", "errormsg": "Connection timed out"}, "h3")
        assert izid["ok"] is False
        assert izid["error"] == "curl:28"
        assert izid["message"] == "Connection timed out"

    def test_izdajatelj_pride_iz_polja_certs(self):
        izid = verdicts.curl_verdict(
            {"exitcode": 0, "http_version": "3", "certs": CERTS}, "h3")
        assert izid["subject"] == "CN = cloudflare.com"
        assert "Google Trust Services" in izid["issuer"]

    def test_brez_potrdila_ni_izdajatelja(self):
        assert verdicts.leaf_cert(None) == {"subject": None, "issuer": None}


class TestChromium:
    def test_h3_vsili_izvor_brez_vrat(self):
        """Vrata doda chromium.sh, tako kot pri browse.sh."""
        okolje = verdicts.chromium_env("www.google.com", "h3")
        assert okolje["FORCE_QUIC"] == "www.google.com"
        assert okolje["NO_QUIC"] == ""

    def test_h2_izklopi_quic(self):
        okolje = verdicts.chromium_env("www.google.com", "h2")
        assert okolje["NO_QUIC"] == "1"
        assert okolje["FORCE_QUIC"] == ""

    def test_stran_z_napako_da_kodo(self):
        izid = verdicts.chromium_verdict(ERROR_PAGE, proto="h3")
        assert izid["ok"] is False
        assert izid["error"] == "ERR_INTERNET_DISCONNECTED"

    def test_nalozena_stran_je_uspeh(self):
        izid = verdicts.chromium_verdict(GOOD_PAGE, proto="h2")
        assert izid["ok"] is True
        assert izid["protocol"] == "h2"
        assert izid["title"] == "Cloudflare"

    def test_prazen_izpis_ni_uspeh(self):
        izid = verdicts.chromium_verdict("", proto="h2", returncode=124)
        assert izid["ok"] is False
        assert "124" in izid["message"]

    def test_vmesna_stran_potrdila_se_steje_za_napako(self):
        dom = '<html><body><div id="interstitial-wrapper">ERR_CERT_AUTHORITY_INVALID</div></body></html>'
        assert verdicts.chromium_verdict(dom, proto="h2")["error"] == "ERR_CERT_AUTHORITY_INVALID"


class TestFirefox:
    def test_preslikava_dobi_vse_gostitelje(self):
        okolje = verdicts.firefox_env(["a.com", "www.b.com"], "h3", marionette_port=2828)
        assert okolje["FORCE_QUIC"] == "a.com,www.b.com"
        assert okolje["MARIONETTE_PORT"] == "2828"

    def test_h2_ne_vsili_nicesar(self):
        okolje = verdicts.firefox_env(["a.com"], "h2", marionette_port=2830)
        assert okolje["NO_QUIC"] == "1"
        assert okolje["FORCE_QUIC"] == ""

    def test_protokol_se_prebere_iz_nexthopprotocol(self):
        izid = verdicts.firefox_verdict(
            None, ["Cloudflare", "https://www.cloudflare.com/", "h3"], "h3")
        assert izid["ok"] is True
        assert izid["protocol"] == "h3"

    def test_padec_na_h2_ni_uspeh(self):
        """Vsiljeni h3 velja za tocno ime gostitelja; po preusmeritvi na www ne vec."""
        izid = verdicts.firefox_verdict(
            None, ["Microsoft", "https://www.microsoft.com/", "h2"], "h3")
        assert izid["ok"] is False
        assert izid["error"] == "protokol"

    def test_neterror_da_razlog(self):
        izid = verdicts.firefox_verdict(
            None, ["Napaka", "about:neterror?e=nssFailure2&u=https%3A//a.com/", None], "h2")
        assert izid["ok"] is False
        assert izid["error"] == "nssFailure2"

    def test_napaka_navigacije(self):
        izid = verdicts.firefox_verdict(
            {"error": "unknown error", "message": "Reached error page: about:neterror?e=netTimeout"},
            None, "h3")
        assert izid["ok"] is False
        assert izid["error"] == "netTimeout"


class TestNaslovi:
    def test_cilj_je_vedno_koren_koncnega_gostitelja(self):
        assert verdicts.origin_of("https://www.microsoft.com/sl-si") == "https://www.microsoft.com/"

    def test_prazen_naslov(self):
        assert verdicts.origin_of("") == ""


def probe(client, proto, domain, ok, error=None):
    return {"client": client, "proto": proto, "domain": domain,
            "host": domain, "ok": ok, "error": error}


def index(rows):
    return {(r["client"], r["proto"], r["domain"]): r for r in rows}


class TestPorocilo:
    def test_imenovalec_je_izhodisce(self):
        """Stran, ki ne dela niti brez prestrezanja, ne sme steti v odstotek."""
        base = index([probe("curl", "h3", "a.com", True),
                      probe("curl", "h3", "b.com", False, "curl:28")])
        measured = index([probe("curl", "h3", "a.com", True),
                          probe("curl", "h3", "b.com", False, "curl:28")])
        cell = splet_report.cells(base, measured)[("curl", "h3")]
        assert cell["probed"] == 2
        assert cell["base_ok"] == 1
        assert cell["measured_ok"] == 1
        assert splet_report.pct(cell["measured_ok"], cell["base_ok"]) == "100 %"

    def test_regresija_se_zabelezi(self):
        base = index([probe("chromium", "h2", "a.com", True)])
        measured = index([probe("chromium", "h2", "a.com", False, "ERR_CERT_AUTHORITY_INVALID")])
        cell = splet_report.cells(base, measured)[("chromium", "h2")]
        assert cell["measured_ok"] == 0
        assert [item["error"] for item in cell["broken"]] == ["ERR_CERT_AUTHORITY_INVALID"]

    def test_kar_dela_sele_v_b1_ni_regresija(self):
        base = index([probe("curl", "h2", "a.com", False, "curl:28")])
        measured = index([probe("curl", "h2", "a.com", True)])
        cell = splet_report.cells(base, measured)[("curl", "h2")]
        assert cell["broken"] == []
        assert [item["domain"] for item in cell["recovered"]] == ["a.com"]

    def test_brez_izhodisca_ni_deleza(self):
        assert splet_report.pct(0, 0) == "-"

    def test_stolpci_stevcev_obstajajo_v_programu_p4(self):
        """SWITCH_COLUMNS je vrstni red stolpcev v porocilu in ne vir imen, zato
        ostaja zapisan. Ce se ime razide s programom P4, bi porocilo tiho
        izpisalo nicle, zato tu preverimo, da je podmnozica."""
        assert not set(splet_report.SWITCH_COLUMNS) - set(plot.SWITCH_KEYS)


class TestPonovitev:
    """Prva zahteva na gostitelja se je v poskusu vcasih ustavila do iztaka,
    naslednja pa je stekla takoj; brez ponovitve bi tak raztros pristal v tabeli."""

    def run(self, izidi, retries):
        preostali = list(izidi)

        async def probe():
            return dict(preostali.pop(0))

        return asyncio.run(with_retry(probe, retries, pause=0))

    def test_uspeh_se_ne_ponovi(self):
        izid = self.run([{"ok": True}, {"ok": True}], retries=1)
        assert izid["attempts"] == 1

    def test_prehoden_neuspeh_se_popravi(self):
        izid = self.run([{"ok": False}, {"ok": True}], retries=1)
        assert izid["ok"] is True
        assert izid["attempts"] == 2

    def test_trajen_neuspeh_ostane_neuspeh(self):
        izid = self.run([{"ok": False}, {"ok": False}], retries=1)
        assert izid["ok"] is False
        assert izid["attempts"] == 2

    def test_brez_ponovitev(self):
        izid = self.run([{"ok": False}], retries=0)
        assert izid["attempts"] == 1


class TestIPv4:
    def test_curl_vztraja_pri_ipv4(self):
        """Postavitev je v celoti IPv4: usmerjanje.p4 zavrze vse, kar ni IPv4."""
        argv = verdicts.curl_argv("https://a.com/", "h2", connect_timeout=5, max_time=20)
        assert "--ipv4" in argv


class TestBrezHibridnegaKljuca:
    """Diagnostika: brez hibridnega kljuca gre firefoxov ClientHello v en datagram."""

    def test_privzeto_izklopljeno(self):
        assert verdicts.firefox_env(["a.com"], "h3", marionette_port=2828)["NO_KYBER"] == ""

    def test_vklop_gre_v_okolje(self):
        env = verdicts.firefox_env(["a.com"], "h3", marionette_port=2828, no_kyber=True)
        assert env["NO_KYBER"] == "1"


class TestNapakaStreznika:
    """Posrednik ob neuspeli povezavi navzgor sam vrne 502. Odjemalec jo dobi po
    zahtevanem protokolu, zato bi brez tega merila stela za delujoco stran."""

    def test_curl_koda_petsto(self):
        izid = verdicts.curl_verdict(
            {"exitcode": 0, "http_version": "3", "http_code": 502}, "h3")
        assert izid["ok"] is False
        assert izid["error"] == "http:502"

    def test_brskalnik_prepozna_stran_posrednika(self):
        dom = "<html><head><title>502 Bad Gateway</title></head><body>x</body></html>"
        assert verdicts.chromium_verdict(dom, proto="h3")["error"] == "http:502"

    def test_firefox_prepozna_stran_posrednika(self):
        izid = verdicts.firefox_verdict(
            None, ["502 Bad Gateway", "https://a.com/", "h3"], "h3")
        assert izid["error"] == "http:502"

    def test_preusmeritev_ostane_uspeh(self):
        assert verdicts.server_error(301) is None
        assert verdicts.server_error(404) is None
        assert verdicts.server_error(title="Cloudflare") is None

    def test_porocilo_popravi_ze_zapisane_vrstice(self):
        vrstica = {"ok": True, "http_code": 502, "domain": "a.com"}
        assert splet_report.recheck(vrstica)["ok"] is False
        cela = {"ok": True, "http_code": 200, "title": "Cloudflare"}
        assert splet_report.recheck(cela)["ok"] is True


def apex(domain, reachable=True):
    return {"domain": domain, "reachable": reachable, "via": "apex",
            "host": domain, "url": f"https://{domain}/",
            "http_code": 200 if reachable else None,
            "error": None if reachable else "curl:6", "message": None}


def check(h2, h3):
    return {"h2": {"ok": h2, "protocol": "h2" if h2 else None, "ms": 10,
                   "error": None if h2 else "curl:28", "message": None},
            "h3": {"ok": h3, "protocol": "h3" if h3 else None, "ms": 10,
                   "error": None if h3 else "curl:28", "message": None}}


class TestIzborNabora:
    """Vsak protokol ima svoj nabor, ker ju splet ne ponuja v enaki meri."""

    def sestavljen(self):
        return nabor(
            {"source": "izvoz.csv"},
            [apex("oba.com"), apex("samo2.com"), apex("samo3.com"),
             apex("nic.com"), apex("mrtva.com", reachable=False)],
            {"oba.com": check(True, True), "samo2.com": check(True, False),
             "samo3.com": check(False, True), "nic.com": check(False, False)},
        )

    def test_v_naboru_je_le_kar_kje_deluje(self):
        domene = [item["domain"] for item in self.sestavljen()["targets"]]
        assert domene == ["oba.com", "samo2.com", "samo3.com"]

    def test_statistika_loci_protokola(self):
        stats = self.sestavljen()["stats"]
        assert stats["domains"] == 5
        assert stats["reachable"] == 4
        assert (stats["h2"], stats["h3"], stats["both"]) == (2, 2, 1)
        assert (stats["h2_only"], stats["h3_only"]) == (1, 1)
        assert stats["selected"] == 3

    def test_izvor_ostane_v_naboru(self):
        assert self.sestavljen()["source"] == "izvoz.csv"

    def test_vzorec_je_iz_domen_ki_delujejo_po_obeh(self, tmp_path):
        """Vzorec mora biti primerljiv med protokoloma, zato so v njem le domene,
        ki v izboru delujejo po obeh."""
        path = tmp_path / "nabor.json"
        path.write_text(json.dumps(self.sestavljen()), encoding="utf-8")
        for proto in ("h2", "h3"):
            vzorec = load_targets(path, 0, proto, sample=2, seed=1234)
            assert [cilj.domain for cilj in vzorec] == ["oba.com"]

    def test_vzorec_je_pri_istem_semenu_vedno_isti(self, tmp_path):
        path = tmp_path / "nabor.json"
        oba = [{"domain": f"d{i}.com", "reachable": True, **check(True, True)}
               for i in range(20)]
        path.write_text(json.dumps({"targets": oba}), encoding="utf-8")
        prvi = [cilj.domain for cilj in load_targets(path, 0, "h2", sample=5, seed=1234)]
        drugi = [cilj.domain for cilj in load_targets(path, 0, "h3", sample=5, seed=1234)]
        assert len(prvi) == 5
        assert prvi == drugi
        assert prvi != [cilj.domain for cilj
                        in load_targets(path, 0, "h2", sample=5, seed=7)]

    def test_cilji_se_filtrirajo_po_protokolu(self, tmp_path):
        path = tmp_path / "nabor.json"
        path.write_text(json.dumps(self.sestavljen()), encoding="utf-8")
        assert [t.domain for t in load_targets(path, 0, "h2")] == ["oba.com", "samo2.com"]
        assert [t.domain for t in load_targets(path, 0, "h3")] == ["oba.com", "samo3.com"]
        assert len(load_targets(path, 0)) == 3


class TestSamoHttp2:
    """Domena, ki v merjeni postavitvi dela po HTTP/2 in ne po HTTP/3, kaze ceno
    prestrezanja prometa QUIC. Domena, ki QUIC sploh ne ponuja, v to ne sodi."""

    def test_neuspeh_pri_h3_se_zabelezi(self):
        measured = index([probe("curl", "h2", "a.com", True),
                          probe("curl", "h3", "a.com", False, "curl:28")])
        assert [item["domain"] for item in splet_report.only_h2(measured)["curl"]] \
            == ["a.com"]

    def test_domena_brez_h3_v_naboru_ne_steje(self):
        measured = index([probe("curl", "h2", "a.com", True)])
        assert splet_report.only_h2(measured) == {}

    def test_kadar_delujeta_oba_ni_razlike(self):
        measured = index([probe("curl", "h2", "a.com", True),
                          probe("curl", "h3", "a.com", True)])
        assert splet_report.only_h2(measured) == {}
