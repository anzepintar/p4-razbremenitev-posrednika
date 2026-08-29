from __future__ import annotations

import pytest

import plot
import stats

from conftest import metric_rows, write_cell


class TestPovzetek:

    def test_povprecje_in_interval(self):
        mean, half, n = stats.summary([1, 2, 3, 4, 5])
        assert mean == pytest.approx(3.0)
        assert half == pytest.approx(1.9629, abs=1e-4)
        assert n == 5

    def test_en_sam_tek_nima_intervala(self):
        assert stats.summary([7.0]) == (7.0, None, 1)

    def test_prazno_nima_nicesar(self):
        assert stats.summary([]) == (None, None, 0)
        assert stats.summary([None, None]) == (None, None, 0)

    def test_manjkajoce_vrednosti_izpadejo(self):
        mean, half, n = stats.summary([None, 2.0, None, 4.0])
        assert mean == pytest.approx(3.0)
        assert n == 2
        assert half == pytest.approx(stats.T95[1], abs=1e-3)

    def test_enake_vrednosti_dajo_nicelni_interval(self):
        assert stats.summary([5.0, 5.0, 5.0])[1] == pytest.approx(0.0)

    def test_veliki_vzorec_vzame_normalno(self):
        assert stats.t95(500) == stats.NORMAL


def cell(directory, *, size: int) -> None:
    write_cell(directory, metric_rows(10, duration=10.0, size=size),
               meritev="m4_vrste", postavitev="A0", groups="other",
               workers=1, duration_s=10.0, warmup_s=0.0, rate_rps=10)


class TestZbiranjeTekov:

    def test_teki_se_zdruzijo_v_eno_celico(self, tmp_path):
        for index, size in enumerate((100_000, 200_000, 300_000), start=1):
            cell(tmp_path / f"tek{index}" / "A0" / "h2" / "other", size=size)

        cells = plot.collect(tmp_path)
        assert list(cells) == [("A0", "h2", "other")]

        found = cells[("A0", "h2", "other")]
        assert len(found) == 3
        assert plot.mean(found, "goodput_mbps") == pytest.approx(1.6, abs=0.01)
        assert plot.spread(found, "goodput_mbps") > 0

    def test_brez_tekov_velja_koren(self, tmp_path):
        cell(tmp_path / "A0" / "h2" / "other", size=100_000)
        cells = plot.collect(tmp_path)
        assert len(cells[("A0", "h2", "other")]) == 1
        assert plot.spread(cells[("A0", "h2", "other")], "goodput_mbps") is None

    def test_teki_prevladajo_nad_starimi_izidi(self, tmp_path):
        cell(tmp_path / "A0" / "h2" / "other", size=900_000)
        cell(tmp_path / "tek1" / "A0" / "h2" / "other", size=100_000)
        cells = plot.collect(tmp_path)
        assert len(cells[("A0", "h2", "other")]) == 1
        assert plot.mean(cells[("A0", "h2", "other")], "goodput_mbps") == pytest.approx(0.8)

    def test_povprecje_stevcev_stikala(self, tmp_path):
        for index, value in enumerate((10, 20, 30), start=1):
            directory = tmp_path / f"tek{index}" / "B0" / "h2" / "other"
            cell(directory, size=100_000)
            (directory / "switch_before.json").write_text("{}", encoding="utf-8")
            (directory / "switch_after.json").write_text(
                f'{{"sni_seen": {value}}}', encoding="utf-8")

        found = plot.collect(tmp_path)[("B0", "h2", "other")]
        assert plot.counter_means(found)["sni_seen"] == pytest.approx(20.0)
