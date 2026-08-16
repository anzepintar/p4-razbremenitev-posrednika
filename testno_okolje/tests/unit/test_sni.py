from __future__ import annotations

import pytest

import sni


def write(tmp_path, kind, black=(), white=()):
    (tmp_path / f"{kind}_black.txt").write_text("\n".join(black), encoding="utf-8")
    (tmp_path / f"{kind}_white.txt").write_text("\n".join(white), encoding="utf-8")
    return tmp_path


class TestRead:
    def test_opombe_in_prazne_vrstice_odpadejo(self, tmp_path):
        file = tmp_path / "domain_black.txt"
        file.write_text("# opomba\n\na.com\nb.com # ob strani\n", encoding="utf-8")
        assert sni.read(file) == ["a.com", "b.com"]

    def test_ponovitve_odpadejo_in_je_urejeno(self, tmp_path):
        file = tmp_path / "domain_black.txt"
        file.write_text("b.com\na.com\nb.com\n", encoding="utf-8")
        assert sni.read(file) == ["a.com", "b.com"]

    def test_manjkajoca_datoteka_da_prazen_seznam(self, tmp_path):
        assert sni.read(tmp_path / "ni.txt") == []


class TestLoad:
    def test_ista_domena_na_obeh_seznamih_je_napaka(self, tmp_path):
        write(tmp_path, "domain", black=["a.com"], white=["a.com"])
        with pytest.raises(sni.SniError, match="hkrati"):
            sni.load("domain", tmp_path)

    def test_neznana_vrsta(self, tmp_path):
        with pytest.raises(sni.SniError, match="neznana vrsta"):
            sni.load("cudno", tmp_path)

    def test_naslovi_dobijo_predpono(self, tmp_path):
        write(tmp_path, "ip", black=["10.0.2.10"], white=["10.0.9.0/24"])
        loaded = sni.load("ip", tmp_path)
        assert loaded["black"] == ["10.0.2.10/32"]
        assert loaded["white"] == ["10.0.9.0/24"]


class TestEntry:

    def test_tocno_ime_ima_polno_masko(self):
        value, mask, priority = sni.entry("a.com")
        assert len(value) == sni.KEY_BYTES
        assert value.endswith(b"a.com") and value[0] == 0
        assert mask == b"\xff" * sni.KEY_BYTES
        assert priority == sni.KEY_BYTES + len("a.com")

    def test_zacetna_pika_da_masko_pripone(self):
        value, mask, priority = sni.entry(".primer.com")
        assert value.endswith(b".primer.com")
        assert mask.count(255) == len(".primer.com")
        assert mask.endswith(b"\xff" * len(".primer.com"))
        assert priority == len(".primer.com")

    def test_tocno_ime_ima_visjo_prednost_kot_pripona(self):
        _, _, exact = sni.entry("a.primer.com")
        _, _, suffix = sni.entry(".primer.com")
        assert exact > suffix

    def test_predolgo_ime_je_napaka(self):
        with pytest.raises(sni.SniError, match="daljsi"):
            sni.entry("x" * (sni.KEY_BYTES + 1))

    def test_prazen_vzorec_je_napaka(self):
        with pytest.raises(sni.SniError, match="prazen"):
            sni.entry("")

    def test_match_je_zapis_za_p4runtime(self):
        assert sni.match("a.com").startswith("0x")
        assert "&&&" in sni.match("a.com")


class TestIgnoreHosts:

    def test_prazen_seznam_da_prazen_vzorec(self):
        assert sni.ignore_hosts([]) == ""

    def test_vzorec_je_sidran_in_ima_vrata(self):
        pattern = sni.ignore_hosts(["primer.com"])
        assert pattern.startswith("^") and pattern.endswith(f":{sni.TLS_PORT}$")

    def test_ujame_natanko_domeno_z_vrati(self):
        import re

        pattern = re.compile(sni.ignore_hosts(["primer.com", ".apk.si"]))
        assert pattern.match("primer.com:443")
        assert pattern.match("a.apk.si:443")
        assert not pattern.match("primer.com:80")
        assert not pattern.match("zloprimer.com:443")

    def test_naslovi_gredo_v_isti_vzorec(self):
        import re

        pattern = re.compile(sni.ignore_hosts(["primer.com"], ["10.0.2.12/32"]))
        assert pattern.match("10.0.2.12:443")
        assert pattern.match("primer.com:443")
        assert not pattern.match("10.0.2.13:443")

    def test_predpona_32_postane_gol_naslov(self):
        assert "/32" not in sni.ignore_hosts([], ["10.0.2.12/32"])

    def test_sami_naslovi_brez_domen(self):
        assert sni.ignore_hosts([], ["10.0.2.12/32"]) != ""


class TestBlockFilter:

    def test_prazna_seznama_dasta_prazen_vzorec(self):
        assert sni.block_filter([], []) == ""

    def test_vzorec_je_sidran(self):
        pattern = sni.block_filter(["primer.com"])
        assert pattern.startswith("^") and pattern.endswith("$")

    def test_brez_vrat(self):
        assert ":443" not in sni.block_filter(["primer.com"])

    def test_ujame_tocno_ime_in_ne_sosednjih(self):
        import re

        pattern = re.compile(sni.block_filter(["primer.com"]))
        assert pattern.search("primer.com")
        assert not pattern.search("zloprimer.com")
        assert not pattern.search("primer.com.si")

    def test_pika_ujame_poddomene_ne_pa_korena(self):
        import re

        pattern = re.compile(sni.block_filter([".primer.com"]))
        assert pattern.search("a.primer.com")
        assert not pattern.search("primer.com")

    def test_naslovi_gredo_v_isti_vzorec(self):
        import re

        pattern = re.compile(sni.block_filter(["primer.com"], ["10.0.2.11/32"]))
        assert pattern.search("10.0.2.11")
        assert pattern.search("primer.com")
        assert not pattern.search("10.0.2.10")


class TestSkladnostSStikalom:

    def switch_matches(self, pattern: str, name: str) -> bool:
        value, mask, _ = sni.entry(pattern)
        probe = name.encode().rjust(sni.KEY_BYTES, b"\x00")
        return bytes(a & m for a, m in zip(probe, mask)) == bytes(
            a & m for a, m in zip(value, mask)
        )

    def proxy_matches(self, pattern: str, name: str) -> bool:
        import re

        return bool(re.search(sni.block_filter([pattern]), name))

    @pytest.mark.parametrize("pattern,name", [
        ("primer.com", "primer.com"),
        ("primer.com", "a.primer.com"),
        ("primer.com", "zloprimer.com"),
        (".primer.com", "a.primer.com"),
        (".primer.com", "primer.com"),
        (".primer.com", "b.a.primer.com"),
    ])
    def test_isti_izid(self, pattern, name):
        assert self.switch_matches(pattern, name) == self.proxy_matches(pattern, name), (
            f"stikalo in posrednik se razhajata pri vzorcu {pattern!r} in imenu {name!r}"
        )
