from __future__ import annotations

import pytest
import yaml

import experiment as exp

BASE = {
    "domains": {"total": 10, "groups": {"ip_black": 2, "sni_black": 2, "unknown": 6}},
    "server_ips": {"default": "10.0.2.10", "ip_black": "10.0.2.11",
                   "ip_white": "10.0.2.12"},
    "protocols": {"h2": 0.0, "h3": 1.0},
    "modes": ["brez", "ip_black", "sni_black"],
    "load": {"connect_timeout_s": 3.0, "max_time_s": 10, "object_kb": 0},
    "run": {"seed": 1, "out": "/tmp/out", "cacert": "/tmp/ca.pem",
            "testset": "/tmp/testset", "subset": "testni"},
}


def config(tmp_path, **overrides):
    data = {**BASE, **overrides}
    path = tmp_path / "experiment.yml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def testset(tmp_path, count: int):
    root = tmp_path / "testset" / "testni"
    root.mkdir(parents=True)
    for index in range(count):
        (root / f"d{index}.com").mkdir()
    return tmp_path / "testset"


class TestLoad:
    def test_prebere_vrednosti(self, tmp_path):
        settings = exp.load(config(tmp_path))
        assert settings.modes == ["brez", "ip_black", "sni_black"]
        assert settings.protocols == {"h2": 0.0, "h3": 1.0}
        assert settings.connect_timeout_s == 3.0
        assert settings.max_time_s == 10.0
        assert settings.total == 10

    def test_vsota_skupin_cez_total_je_napaka(self, tmp_path):
        path = config(tmp_path, domains={"total": 3, "groups": {"a": 2, "b": 2}})
        with pytest.raises(exp.ExperimentError, match="presega"):
            exp.load(path)

    def test_naslov_skupine(self, tmp_path):
        settings = exp.load(config(tmp_path))
        assert settings.ip_for("ip_black") == "10.0.2.11"
        assert settings.ip_for("unknown") == "10.0.2.10"


class TestNacini:

    def test_neznan_nacin_je_napaka(self, tmp_path):
        path = config(tmp_path, modes=["brez", "ni_taksne"])
        with pytest.raises(exp.ExperimentError, match="modes pozna"):
            exp.load(path)

    def test_nacin_brez_domen_je_napaka(self, tmp_path):
        path = config(tmp_path, modes=["brez", "ip_white"])
        with pytest.raises(exp.ExperimentError, match="nimajo domen"):
            exp.load(path)

    def test_brez_seznama_vzame_kar_razdelitev_zmore(self, tmp_path):
        data = {k: v for k, v in BASE.items() if k != "modes"}
        path = tmp_path / "experiment.yml"
        path.write_text(yaml.safe_dump(data), encoding="utf-8")
        assert exp.load(path).modes == ["brez", "ip_black", "sni_black"]

    def test_izhodisce_ne_potrebuje_skupine(self, tmp_path):
        assert "brez" not in exp.load(config(tmp_path)).groups


class TestAssign:
    def test_vsaka_skupina_dobi_svoje_stevilo(self, tmp_path):
        settings = exp.load(config(tmp_path))
        data = exp.build(settings, testset=testset(tmp_path, 10))
        assert data["counts"] == {"ip_black": 2, "sni_black": 2, "unknown": 6}

    def test_presezek_pade_v_unknown(self, tmp_path):
        settings = exp.load(config(tmp_path, domains={
            "total": 10, "groups": {"ip_black": 2}}, modes=["brez", "ip_black"]))
        data = exp.build(settings, testset=testset(tmp_path, 10))
        assert data["counts"] == {"ip_black": 2, "unknown": 8}

    def test_premalo_domen_je_napaka(self, tmp_path):
        settings = exp.load(config(tmp_path))
        with pytest.raises(exp.ExperimentError, match="terjajo"):
            exp.build(settings, testset=testset(tmp_path, 3))

    def test_razdelitev_je_ponovljiva(self, tmp_path):
        settings = exp.load(config(tmp_path))
        root = testset(tmp_path, 10)
        assert exp.build(settings, testset=root) == exp.build(settings, testset=root)

    def test_skupine_se_ne_prekrivajo(self, tmp_path):
        settings = exp.load(config(tmp_path))
        data = exp.build(settings, testset=testset(tmp_path, 10))
        groups = exp.by_group(data)
        seen = [d for names in groups.values() for d in names]
        assert len(seen) == len(set(seen)) == 10

    def test_naslov_sledi_skupini(self, tmp_path):
        settings = exp.load(config(tmp_path))
        data = exp.build(settings, testset=testset(tmp_path, 10))
        for domain, info in data["domains"].items():
            expected = "10.0.2.11" if info["group"] == "ip_black" else "10.0.2.10"
            assert info["ip"] == expected

    def test_spremenjeno_razmerje_spremeni_razdelitev(self, tmp_path):
        root = testset(tmp_path, 10)
        modes = ["brez", "ip_black"]
        few = exp.build(exp.load(config(tmp_path, modes=modes, domains={
            "total": 10, "groups": {"ip_black": 2, "unknown": 8}})), testset=root)
        many = exp.build(exp.load(config(tmp_path, modes=modes, domains={
            "total": 10, "groups": {"ip_black": 5, "unknown": 5}})), testset=root)
        assert few["counts"]["ip_black"] == 2
        assert many["counts"]["ip_black"] == 5


class TestObjectKb:

    def test_privzeto_nic(self, tmp_path):
        assert exp.load(config(tmp_path)).object_kb == 0

    def test_prebere_vrednost(self, tmp_path):
        path = config(tmp_path, load={**BASE["load"], "object_kb": 10240})
        assert exp.load(path).object_kb == 10240


class TestProtokoli:

    def test_delez_izven_obmocja_je_napaka(self, tmp_path):
        path = config(tmp_path, protocols={"h2": 0.0, "h3": 1.5})
        with pytest.raises(exp.ExperimentError, match="med 0 in 1"):
            exp.load(path)
