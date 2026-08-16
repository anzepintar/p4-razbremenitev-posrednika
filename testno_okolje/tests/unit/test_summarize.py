from __future__ import annotations

from runner import summarize


def row(group, *, expect_blocked, exitcode=0, blocked=False, http_code=200,
        document=True, url=None, time_total=0.1):
    return {
        "group": group,
        "expect_blocked": expect_blocked,
        "exitcode": exitcode,
        "blocked": blocked,
        "http_code": http_code,
        "document": document,
        "url": url or ("https://x/index.html" if document else "https://x/_asset.bin"),
        "time_total": time_total,
        "size_download": 1000,
    }


class TestIsDocument:
    def test_izrecna_oznaka_ima_prednost(self):
        assert summarize.is_document({"document": True, "url": "https://x/a.bin"})
        assert not summarize.is_document({"document": False, "url": "https://x/index.html"})

    def test_brez_oznake_se_sklepa_iz_naslova(self):
        assert summarize.is_document({"url": "https://x/index.html"})
        assert not summarize.is_document({"url": "https://x/_asset.bin"})


class TestByGroup:
    def test_uspela_zahteva_v_dovoljeni_skupini_je_pricakovana(self):
        out = summarize.by_group([row("unknown", expect_blocked=False)])
        assert out["unknown"]["as_expected_pct"] == 100.0

    def test_iztek_v_blokirani_skupini_je_pricakovan(self):
        rows = [row("sni_black", expect_blocked=True, exitcode=28, http_code=0)]
        assert summarize.by_group(rows)["sni_black"]["as_expected_pct"] == 100.0

    def test_403_z_oznako_steje_kot_blokada(self):
        rows = [row("content_block", expect_blocked=True, blocked=True, http_code=403)]
        out = summarize.by_group(rows)["content_block"]
        assert out["stopped"] == 1
        assert out["as_expected_pct"] == 100.0

    def test_uspela_zahteva_v_blokirani_skupini_ni_pricakovana(self):
        rows = [row("ip_black", expect_blocked=True)]
        assert summarize.by_group(rows)["ip_black"]["as_expected_pct"] == 0.0

    def test_502_ni_blokada_ampak_okvara(self):
        rows = [row("ip_black", expect_blocked=True, http_code=502)]
        out = summarize.by_group(rows)["ip_black"]
        assert out["upstream_fail"] == 1
        assert out["stopped"] == 0
        assert out["as_expected_pct"] == 0.0

    def test_skupine_se_stejejo_loceno(self):
        rows = [
            row("unknown", expect_blocked=False),
            row("unknown", expect_blocked=False),
            row("sni_black", expect_blocked=True, exitcode=28, http_code=0),
        ]
        out = summarize.by_group(rows)
        assert out["unknown"]["requests"] == 2
        assert out["sni_black"]["requests"] == 1

    def test_delez_je_povprecje_in_ne_vse_ali_nic(self):
        rows = [
            row("sni_black", expect_blocked=True, exitcode=28, http_code=0),
            row("sni_black", expect_blocked=True),
        ]
        assert summarize.by_group(rows)["sni_black"]["as_expected_pct"] == 50.0


class TestPodviriNePokvarijoDeleza:

    def rows(self, subresources: int):
        page = row("content_block", expect_blocked=True, blocked=True, http_code=403)
        assets = [row("content_block", expect_blocked=True, document=False)
                  for _ in range(subresources)]
        return [page, *assets]

    def test_popolna_blokada_je_100_odstotna(self):
        out = summarize.by_group(self.rows(14))["content_block"]
        assert out["as_expected_pct"] == 100.0

    def test_strani_in_podviri_se_stejejo_loceno(self):
        out = summarize.by_group(self.rows(14))["content_block"]
        assert out["pages"] == 1
        assert out["subresources"] == 14
        assert out["requests"] == 15

    def test_delez_ni_odvisen_od_stevila_podvirov(self):
        few = summarize.by_group(self.rows(2))["content_block"]
        many = summarize.by_group(self.rows(30))["content_block"]
        assert few["as_expected_pct"] == many["as_expected_pct"] == 100.0

    def test_neblokirana_stran_med_blokiranimi_se_pozna(self):
        rows = self.rows(14) + [row("content_block", expect_blocked=True)]
        out = summarize.by_group(rows)["content_block"]
        assert out["pages"] == 2
        assert out["as_expected_pct"] == 50.0
