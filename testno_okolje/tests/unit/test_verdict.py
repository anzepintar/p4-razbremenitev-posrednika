from __future__ import annotations

import json

import pytest

import verdict


def trial(directory, *, target=100.0, achieved=100.0, requests=100, errors=0,
          duration=12.0, warmup=0.0):
    directory.mkdir(parents=True, exist_ok=True)
    rows = []
    for index in range(requests):
        failed = index < errors
        rows.append({
            "ts": 1000.0 + index * (duration / max(requests, 1)),
            "url": "https://x/index.html", "group": "unknown",
            "expect_blocked": False, "exitcode": 28 if failed else 0,
            "time_appconnect": None if failed else 0.02,
            "time_total": 0.05, "size_download": 0 if failed else 100_000,
        })
    (directory / "metrics.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows))
    (directory / "meta.json").write_text(json.dumps(
        {"duration_s": duration, "warmup_s": warmup, "workers": 16}))
    (directory / "summary.json").write_text(json.dumps(
        {"rate_target_rps": target, "rate_achieved_rps": achieved}))
    return verdict.judge(directory)


class TestMerilo:

    def test_brez_napak_in_z_doseglo_hitrostjo_je_vzdrzno(self, tmp_path):
        assert trial(tmp_path)["ok"] is True

    def test_ena_napaka_pokvari_poskus(self, tmp_path):
        result = trial(tmp_path, errors=1)
        assert result["ok"] is False
        assert "napak" in result["reason"]

    def test_prenizka_dosezena_hitrost_pokvari_poskus(self, tmp_path):
        result = trial(tmp_path, target=100.0, achieved=90.0)
        assert result["ok"] is False
        assert "doseglo" in result["reason"]

    def test_majhno_zaostajanje_je_se_sprejemljivo(self, tmp_path):
        assert trial(tmp_path, target=100.0, achieved=99.0)["ok"] is True

    def test_brez_meritev_ni_vzdrzno(self, tmp_path):
        (tmp_path / "meta.json").write_text(json.dumps({"duration_s": 12, "warmup_s": 0}))
        assert verdict.judge(tmp_path)["ok"] is False

    def test_sodba_hrani_stevilke_za_graf(self, tmp_path):
        result = trial(tmp_path, target=100.0, achieved=99.5)
        assert result["target_rps"] == 100.0
        assert result["achieved_rps"] == 99.5
        assert result["errors_pct"] == 0
        assert result["total_p95_ms"] is not None


class TestZapis:

    def test_zapise_verdict_json_in_vrne_kodo(self, tmp_path):
        trial(tmp_path)
        assert verdict.main([str(tmp_path)]) == 0
        assert json.loads((tmp_path / "verdict.json").read_text())["ok"] is True

    def test_padel_poskus_vrne_neniclo(self, tmp_path):
        trial(tmp_path, errors=5)
        assert verdict.main([str(tmp_path)]) == 1
        assert json.loads((tmp_path / "verdict.json").read_text())["ok"] is False
