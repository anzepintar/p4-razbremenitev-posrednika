from __future__ import annotations

import asyncio
import json
import random
import time

import pytest

import plot
from conftest import SIZE, metric_rows, write_cell
from runner.__main__ import RequestPacer
from runner.scenario import (
    ScenarioError, Scenario, Site, build_pool, parse_groups,
)

DURATION = 30.0
SWITCH_ZERO = {key: 0 for key in plot.SWITCH_KEYS}


def scenario(groups: dict[str, int]) -> Scenario:
    sites = {}
    for group, count in groups.items():
        for index in range(count):
            domain = f"{group}{index}.example"
            sites[domain] = Site(domain=domain, group=group, ip="10.0.2.10")
    return Scenario(sites=sites, run=None, quic_share=0.0)


class TestRequestPacer:

    def test_brez_cilja_ne_caka(self):
        async def go():
            pacer = RequestPacer(None)
            started = time.monotonic()
            for _ in range(50):
                await pacer.account()
            return time.monotonic() - started, pacer.done

        elapsed, done = asyncio.run(go())
        assert done == 50
        assert elapsed < 0.2

    def test_zadrzi_na_ciljno_frekvenco(self):
        async def go():
            pacer = RequestPacer(50)
            started = time.monotonic()
            for _ in range(10):
                await pacer.account()
            return time.monotonic() - started, pacer.achieved_rps

        elapsed, achieved = asyncio.run(go())
        assert elapsed >= 0.15
        assert achieved == pytest.approx(50, rel=0.5)

    def test_steje_tudi_brez_cilja(self):
        async def go():
            pacer = RequestPacer(None)
            await pacer.account()
            await pacer.account()
            return pacer.achieved_rps

        assert asyncio.run(go()) > 0


class TestIzbiraSkupin:

    def test_vrne_samo_zahtevane_skupine(self):
        pool = scenario({"sni_black": 3, "unknown": 2}).domains_in(["sni_black"])
        assert pool == ["sni_black0.example", "sni_black1.example", "sni_black2.example"]

    def test_vec_skupin_hkrati(self):
        pool = scenario({"sni_black": 1, "ip_black": 1, "unknown": 1}).domains_in(
            ["sni_black", "ip_black"]
        )
        assert pool == ["ip_black0.example", "sni_black0.example"]

    def test_neznana_skupina_je_napaka(self):
        with pytest.raises(ScenarioError, match="ni"):
            scenario({"unknown": 1}).domains_in(["ni_taksne"])

    def test_prazna_skupina_je_napaka(self):
        with pytest.raises(ScenarioError, match="gen_lists"):
            scenario({"unknown": 2}).domains_in(["sni_black"])


class TestMesanica:

    def pool(self, spec: str):
        sites = scenario({"unknown": 4, "sni_white": 2, "ip_black": 1})
        return build_pool(sites, parse_groups(spec))

    def test_brez_skupin_vzame_ves_nabor(self):
        sites = scenario({"unknown": 2, "sni_white": 1})
        assert len(build_pool(sites, None).domains[""]) == 3

    def test_ena_skupina_ostane_enakomerna(self):
        pool = self.pool("unknown")
        rng = random.Random(0)
        picks = {pool.pick(rng) for _ in range(200)}
        assert picks == set(pool.domains["unknown"])

    def test_utezi_dolocajo_razmerja(self):
        pool = self.pool("unknown:80,sni_white:20")
        rng = random.Random(1234)
        picks = [pool.pick(rng) for _ in range(4000)]
        share = sum(1 for p in picks if p.startswith("unknown")) / len(picks)
        assert share == pytest.approx(0.80, abs=0.03)

    def test_utez_nic_izpade_iz_nabora(self):
        pool = self.pool("unknown:1,ip_black:0")
        assert "ip_black" not in pool.domains

    def test_brez_utezi_so_skupine_enakovredne(self):
        assert self.pool("unknown,sni_white").weights == (1.0, 1.0)

    def test_neznana_utez_je_napaka(self):
        with pytest.raises(ScenarioError, match="ni stevilo"):
            parse_groups("unknown:veliko")

    def test_same_nicle_so_napaka(self):
        with pytest.raises(ScenarioError, match="nic"):
            parse_groups("unknown:0,sni_white:0")

    def test_negativna_utez_je_napaka(self):
        with pytest.raises(ScenarioError, match="negativne"):
            parse_groups("unknown:-1")


def link(byte_count: int = 0) -> dict:
    return {"rx_packets": byte_count // 1400, "tx_packets": 0,
            "rx_bytes": byte_count, "tx_bytes": 0}


CLIENT_BYTES = 12_000_000


def cell_run(directory, *, requests: int = 100, duration: float = DURATION,
             warmup: float = 0.0, blocked: bool = False, stopped_share: float = 1.0,
             cpu_ms: float = 1_500.0, quota: float | None = 2.0,
             proxy_bytes: int | None = None, switch_after: dict | None = None,
             flows: int = 0, node: str = "mitm"):
    rows = metric_rows(requests, duration=duration,
                       group="sni_black" if blocked else "unknown",
                       expect_blocked=blocked,
                       failures=int(requests * stopped_share) if blocked else 0)
    write_cell(directory, rows, meritev="test", postavitev="B0", groups="unknown",
               workers=16, duration_s=duration, warmup_s=warmup)

    (directory / "links_before.json").write_text(json.dumps(
        {"client": {"eth1": link()}, "mitm": {"eth1": link()}}))
    (directory / "links_after.json").write_text(json.dumps(
        {"client": {"eth1": link(CLIENT_BYTES)},
         "mitm": {"eth1": link(CLIENT_BYTES if proxy_bytes is None else proxy_bytes)}}))

    after = {"usage_usec": int(cpu_ms * 1000)}
    if quota is not None:
        after["cpu_quota"] = quota
    (directory / "cpu_before.json").write_text(json.dumps({node: {"usage_usec": 0}}))
    (directory / "cpu_after.json").write_text(json.dumps({node: after}))

    if switch_after is not None:
        (directory / "switch_before.json").write_text(json.dumps(SWITCH_ZERO))
        (directory / "switch_after.json").write_text(json.dumps(switch_after))
    if flows:
        (directory / "proxy_flows.jsonl").write_text(
            "".join(json.dumps({"ts": 1.0, "host": "x"}) + "\n" for _ in range(flows)))
    return plot.load_cell(directory)


class TestIzracunCelice:
    def test_hitrost_deli_s_trajanjem_in_ne_z_razponom(self, tmp_path):
        cell = cell_run(tmp_path, requests=100)
        assert cell["duration_s"] == DURATION
        assert cell["goodput_mbps"] == pytest.approx(100 * SIZE * 8 / DURATION / 1e6, rel=0.01)

    def test_ogrevanje_izpade_iz_okna(self, tmp_path):
        cell = cell_run(tmp_path, requests=100, warmup=DURATION / 2)
        assert cell["duration_s"] == DURATION / 2
        assert cell["requests"] == 50

    def test_blokirani_promet_ne_steje_v_propustnost(self, tmp_path):
        cell = cell_run(tmp_path, requests=100, blocked=True)
        assert cell["goodput_mbps"] == 0.0
        assert cell["requests"] == 100

    def test_cpu_je_na_poslano_zahtevo_tudi_ce_ni_prisla_do_posrednika(self, tmp_path):
        cell = cell_run(tmp_path, requests=100, blocked=True, cpu_ms=1_500.0,
                        proxy_bytes=0)
        assert cell["proxy_kb_per_request"] == 0.0
        assert cell["cpu_ms_per_request_mitm"] == pytest.approx(15.0)

    def test_cpu_je_razlika_in_ne_absolutna_vrednost(self):
        before = {"mitm": {"usage_usec": 900_000_000}}
        after = {"mitm": {"usage_usec": 915_000_000}}
        assert plot.cpu_delta(before, after)["mitm"]["cpu_ms"] == pytest.approx(15_000.0)

    def test_izraba_je_jedra_deljena_s_kvoto(self, tmp_path):
        cell = cell_run(tmp_path, duration=30.0, cpu_ms=15_000.0, quota=2.0)
        assert cell["cpu_util_mitm"] == pytest.approx(0.25, abs=0.01)

    def test_brez_kvote_izrabe_ni(self, tmp_path):
        assert cell_run(tmp_path, quota=None)["cpu_util_mitm"] is None

    def test_manjkajoce_vozlisce_ni_nic(self, tmp_path):
        assert cell_run(tmp_path)["cpu_ms_per_request_switch"] is None

    def test_promet_do_posrednika_na_zahtevo(self, tmp_path):
        cell = cell_run(tmp_path, requests=100, proxy_bytes=1024 * 500)
        assert cell["proxy_kb_per_request"] == pytest.approx(5.0)

    def test_pravilnost_politike(self, tmp_path):
        assert cell_run(tmp_path, blocked=True, stopped_share=1.0)["policy_ok_pct"] == 100.0

    def test_pravilnost_pade_ko_blokada_ne_ujame(self, tmp_path):
        assert cell_run(tmp_path, blocked=True, stopped_share=0.5)["policy_ok_pct"] == 50.0

    def test_prazna_celica_ni_celica(self, tmp_path):
        (tmp_path / "meta.json").write_text(json.dumps({"duration_s": 10, "warmup_s": 0}))
        assert plot.load_cell(tmp_path) is None


class TestStevciStikala:
    def test_odsteje_zacetno_stanje(self):
        before = {key: 100_000 for key in plot.SWITCH_KEYS}
        after = dict(before, ip_blocked=100_300, sni_seen=101_000)
        assert plot.counter_delta(before, after)["ip_blocked"] == 300
        assert plot.counter_delta(before, after)["sni_seen"] == 1000

    def test_celica_hrani_razliko_in_ne_kumulative(self, tmp_path):
        cell = cell_run(tmp_path, switch_after=dict(SWITCH_ZERO, ip_blocked=300))
        assert cell["switch"]["ip_blocked"] == 300

    def test_brez_stikala_ni_stevcev(self, tmp_path):
        assert cell_run(tmp_path)["switch"] == {}


class TestPragRentabilnosti:

    def test_prag_je_tam_kjer_se_bremeni_izenacita(self):
        # A0 pregleda za 10, obide za 4; B0 pregleda za 12, obide za 0.
        point = plot.crossing(10.0, 4.0, 12.0, 0.0)
        assert point == pytest.approx(1 / 3)
        assert (1 - point) * 10 + point * 4 == pytest.approx((1 - point) * 12 + point * 0)

    def test_brez_prihranka_stikalo_dohiti_sele_pri_stotih_odstotkih(self):
        # B0 obide enako drago kot A0, plača pa dodaten skok.
        assert plot.crossing(10.0, 4.0, 12.0, 4.0) == pytest.approx(1.0)

    def test_ce_je_b0_ze_cenejsi_je_prag_pod_nic(self):
        assert plot.crossing(12.0, 6.0, 10.0, 2.0) < 0

    def test_manjkajoca_cena_ne_da_praga(self):
        assert plot.crossing(10.0, None, 12.0, 0.0) is None

    def test_enaka_prihranka_nimata_presecisca(self):
        assert plot.crossing(10.0, 4.0, 12.0, 6.0) is None

    def test_prag_v_razponu_je_odstotek(self):
        assert plot.threshold_label(10.0, 4.0, 12.0, 0.0) == "33.3 %"

    def test_drazji_od_zacetka_do_konca_se_ne_splaca_nikoli(self):
        # B0 zacne drazje in prihrani manj, zato presecisce pade pod nic, a je zunaj razpona.
        assert plot.crossing(13.39, 3.5377, 14.474, 4.905) < 0
        assert plot.threshold_label(13.39, 3.5377, 14.474, 4.905) == "nikoli"

    def test_cenejsi_od_zacetka_se_splaca_vedno(self):
        assert plot.threshold_label(12.0, 6.0, 10.0, 2.0) == "vedno"

    def test_vzporedni_premici_locita_dobicek_od_izgube(self):
        assert plot.threshold_label(12.0, 6.0, 10.0, 4.0) == "vedno"
        assert plot.threshold_label(10.0, 4.0, 12.0, 6.0) == "nikoli"

    def test_manjkajoca_cena_nima_oznake(self):
        assert plot.threshold_label(10.0, None, 12.0, 0.0) == "-"


class TestZbiranje:

    def test_osi_so_v_smiselnem_vrstnem_redu(self):
        cells = {("B0", "h3", "sni_white"): {}, ("A0", "h2", "other"): {},
                 ("C0", "h2", "ip_black"): {}}
        assert plot.axis(cells, 0) == ["C0", "A0", "B0"]
        assert plot.axis(cells, 2) == ["other", "ip_black", "sni_white"]

    def test_hitrosti_in_delezi_se_prebereta_iz_imena(self):
        cells = {("A0", "h2", "r128"): {}, ("A0", "h2", "r16"): {},
                 ("A0", "h2", "potrjeno"): {}, ("A0", "h2", "sni_white_p50"): {},
                 ("A0", "h2", "ip_white_p25"): {}}
        assert plot.rates(cells) == [16, 128]
        assert plot.mix_points(cells, "sni_white") == [50]
        assert plot.mix_points(cells, "ip_white") == [25]
