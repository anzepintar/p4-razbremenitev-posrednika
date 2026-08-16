from __future__ import annotations

import pytest
import yaml

import experiment as exp

BASE = {
    "domains": {"total": 10, "groups": {"ip_black": 2, "sni_black": 2, "unknown": 6}},
    "server_ips": {"default": "10.0.2.10", "ip_black": "10.0.2.11",
                   "ip_white": "10.0.2.12"},
    "traffic": {"cases": {"brez_quic": 0.0, "z_quic": 1.0}},
    "matrix": {"modes": ["brez", "ip_black", "sni_black"], "duration_s": 30,
               "background_mbps": 100, "policy_rps": 50, "repeats": 3},
    "load": {"ramp": [1, 2], "error_budget_pct": 1.0},
    "topologies": ["A0", "B0"],
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
        assert settings.topologies == ["A0", "B0"]
        assert settings.modes == ["brez", "ip_black", "sni_black"]
        assert settings.duration_s == 30
        assert settings.repeats == 3
        assert settings.cases == {"brez_quic": 0.0, "z_quic": 1.0}

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
        path = config(tmp_path, matrix={**BASE["matrix"], "modes": ["brez", "ni_taksne"]})
        with pytest.raises(exp.ExperimentError, match="matrix.modes"):
            exp.load(path)

    def test_nacin_brez_domen_je_napaka(self, tmp_path):
        path = config(tmp_path, matrix={**BASE["matrix"], "modes": ["brez", "ip_white"]})
        with pytest.raises(exp.ExperimentError, match="nimajo domen"):
            exp.load(path)

    def test_brez_seznama_vzame_kar_razdelitev_zmore(self, tmp_path):
        data = {k: v for k, v in BASE.items() if k != "matrix"}
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
            "total": 10, "groups": {"ip_black": 2}},
            matrix={**BASE["matrix"], "modes": ["brez", "ip_black"]}))
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
        modes = {**BASE["matrix"], "modes": ["brez", "ip_black"]}
        few = exp.build(exp.load(config(tmp_path, matrix=modes, domains={
            "total": 10, "groups": {"ip_black": 2, "unknown": 8}})), testset=root)
        many = exp.build(exp.load(config(tmp_path, matrix=modes, domains={
            "total": 10, "groups": {"ip_black": 5, "unknown": 5}})), testset=root)
        assert few["counts"]["ip_black"] == 2
        assert many["counts"]["ip_black"] == 5


class TestObjectKb:

    def test_privzeto_nic(self, tmp_path):
        data = {**BASE}
        data["load"] = {k: v for k, v in BASE["load"].items()}
        path = tmp_path / "experiment.yml"
        path.write_text(yaml.safe_dump(data), encoding="utf-8")
        assert exp.load(path).object_kb == 0

    def test_prebere_vrednost(self, tmp_path):
        path = config(tmp_path, load={**BASE["load"], "object_kb": 10240})
        assert exp.load(path).object_kb == 10240
