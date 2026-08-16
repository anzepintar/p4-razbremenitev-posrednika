from __future__ import annotations

import asyncio
import json
import time

import pytest

import plot
from runner.__main__ import RequestPacer
from runner.scenario import ScenarioError, Scenario, Site

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


def link(packets: int = 0, byte_count: int = 0) -> dict:
    return {"rx_packets": packets, "tx_packets": 0,
            "rx_bytes": byte_count, "tx_bytes": 0}


GROUPS = {"black.example": "ip_black", "ozadje.example": "unknown"}


def cell_run(directory, *, background: int = 10, policy: int = 0,
             blocked: bool = True, verdict: float = 1.0, client_pkts: int = 1000,
             cpu: float = 50.0, switch_after: dict | None = None,
             stopped_share: float = 1.0, flows: list[str] | None = None):
    def row(index, group, expect, exitcode, total):
        return {
            "ts": 1000.0 + index * 0.5,
            "url": "https://x.example/index.html",
            "document": True,
            "group": group,
            "expect_blocked": expect,
            "exitcode": exitcode,
            "time_appconnect": total * 0.4,
            "time_total": total,
            "size_download": 0 if exitcode else 1_000_000,
        }

    (directory / "metrics_ozadje.jsonl").write_text(
        "".join(json.dumps(row(i, "unknown", False, 0, 0.05)) + "\n"
                for i in range(background))
    )
    (directory / "summary_ozadje.json").write_text(
        json.dumps({"duration_s": DURATION, "workers": 16})
    )
    if policy:
        limit = int(policy * stopped_share)
        (directory / "metrics_politika.jsonl").write_text(
            "".join(json.dumps(
                row(i, "ip_black", blocked, 28 if (blocked and i < limit) else 0, verdict)
            ) + "\n" for i in range(policy))
        )
        (directory / "summary_politika.json").write_text(
            json.dumps({"duration_s": DURATION, "workers": 108})
        )

    (directory / "links_before.json").write_text(json.dumps(
        {"client": {"eth1": link()}, "mitm": {"eth1": link()}}))
    (directory / "links_after.json").write_text(json.dumps(
        {"client": {"eth1": link(client_pkts, 12_000_000)},
         "mitm": {"eth1": link(client_pkts), "eth2": link(client_pkts)}}))
    (directory / "nodes.json").write_text(
        json.dumps({"summary": {"mitm": {"cpu_pct_avg": cpu, "mem_mb_avg": 60.0}}})
    )
    if switch_after is not None:
        (directory / "switch_before.json").write_text(json.dumps(SWITCH_ZERO))
        (directory / "switch_after.json").write_text(json.dumps(switch_after))
    if flows is not None:
        (directory / "proxy_flows.jsonl").write_text(
            "".join(json.dumps({"ts": 1.0, "kind": "http", "host": h}) + "\n"
                    for h in flows)
        )
    return plot.load_cell(directory, GROUPS)


class TestIzracunCelice:
    def test_hitrost_deli_s_trajanjem_in_ne_z_razponom(self, tmp_path):
        cell = cell_run(tmp_path, background=10)
        assert cell["duration_s"] == DURATION
        assert cell["goodput_mbps"] == pytest.approx(2.67, abs=0.01)

    def test_hitrost_ne_preseze_zice(self, tmp_path):
        cell = cell_run(tmp_path, background=10)
        assert cell["goodput_mbps"] <= cell["wire_mbps"]

    def test_brez_razbremenitve_ko_gre_vsaka_zahteva_skozi_posrednika(self, tmp_path):
        cell = cell_run(tmp_path, background=10, flows=["ozadje.example"] * 10)
        assert cell["offload_pct"] == pytest.approx(0.0)

    def test_razbremenitev_je_delez_zahtev_brez_seje(self, tmp_path):
        cell = cell_run(tmp_path, background=10, policy=90,
                        flows=["ozadje.example"] * 10)
        assert cell["offload_pct"] == pytest.approx(90.0)

    def test_brez_dnevnika_sej_razbremenitve_ni(self, tmp_path):
        assert cell_run(tmp_path, background=10)["offload_pct"] is None

    def test_cpu_na_zahtevo_steje_oba_tokova(self, tmp_path):
        cell = cell_run(tmp_path, background=10, policy=90, cpu=50.0)
        assert cell["cpu_ms_per_request_mitm"] == pytest.approx(150.0, abs=0.5)

    def test_manjkajoce_vozlisce_ni_nic(self, tmp_path):
        cell = cell_run(tmp_path)
        assert cell["cpu_ms_per_request_switch"] is None

    def test_cas_do_razsodbe(self, tmp_path):
        cell = cell_run(tmp_path, policy=10, verdict=1.0)
        assert cell["verdict_p50_s"] == pytest.approx(1.0)

    def test_brez_politike_ni_razsodbe(self, tmp_path):
        cell = cell_run(tmp_path, policy=0)
        assert cell["verdict_p50_s"] is None
        assert cell["policy_ok_pct"] is None

    def test_pravilnost_politike(self, tmp_path):
        cell = cell_run(tmp_path, policy=10, blocked=True, stopped_share=1.0)
        assert cell["policy_ok_pct"] == 100.0

    def test_pravilnost_pade_ko_blokada_ne_ujame(self, tmp_path):
        cell = cell_run(tmp_path, policy=10, blocked=True, stopped_share=0.5)
        assert cell["policy_ok_pct"] == 50.0
        assert cell["policy_ok_pct"] < plot.VALID_PCT


class TestSejePosrednika:

    def test_ozadje_ne_steje_med_seje_politike(self, tmp_path):
        cell = cell_run(tmp_path, policy=10,
                        flows=["black.example"] * 10 + ["ozadje.example"] * 200)
        assert cell["proxy_sessions"] == 210
        assert cell["proxy_sessions_per_policy_request"] == 1.0

    def test_razbremenjena_politika_nima_sej(self, tmp_path):
        cell = cell_run(tmp_path, policy=10, flows=["ozadje.example"] * 200)
        assert cell["proxy_sessions_per_policy_request"] == 0.0

    def test_vrata_v_imenu_ne_zmotijo(self, tmp_path):
        cell = cell_run(tmp_path, policy=10, flows=["black.example:443"] * 10)
        assert cell["proxy_sessions_per_policy_request"] == 1.0

    def test_naslov_skupine_se_preslika(self):
        lookup = plot.flow_groups({
            "domains": {"a.example": {"group": "unknown"}},
            "server_ips": {"default": "10.0.2.10", "ip_white": "10.0.2.12"},
        })
        assert lookup["a.example"] == "unknown"
        assert lookup["10.0.2.12"] == "ip_white"
        assert "10.0.2.10" not in lookup


class TestStevciStikala:

    def test_odsteje_zacetno_stanje(self, tmp_path):
        before = {key: 100_000 for key in plot.SWITCH_KEYS}
        after = dict(before, ip_blocked=100_300, sni_seen=101_000)
        assert plot.counter_delta(before, after)["ip_blocked"] == 300
        assert plot.counter_delta(before, after)["sni_seen"] == 1000

    def test_celica_hrani_razliko_in_ne_kumulative(self, tmp_path):
        cell = cell_run(tmp_path, switch_after=dict(SWITCH_ZERO, ip_blocked=300))
        assert cell["switch"]["ip_blocked"] == 300

    def test_brez_stikala_ni_stevcev(self, tmp_path):
        assert cell_run(tmp_path)["switch"] == {}


class TestPrednost:

    def test_razbremenitev_kot_odstotne_tocke(self):
        data = {("A0", "h2", "ip_black"): {"offload_pct": {"med": 2.0}},
                ("B0", "h2", "ip_black"): {"offload_pct": {"med": 99.7}}}
        got = plot.advantage(data, "offload_pct", "h2", "ip_black", True, "delta",
                             ["A0", "B0"])
        assert got == pytest.approx(97.7)

    def test_manjse_je_boljse_da_veckratnik_nad_ena(self):
        data = {("A0", "h2", "brez"): {"total_p50_ms": {"med": 40.0}},
                ("B0", "h2", "brez"): {"total_p50_ms": {"med": 20.0}}}
        got = plot.advantage(data, "total_p50_ms", "h2", "brez", False, "ratio",
                             ["A0", "B0"])
        assert got == pytest.approx(2.0)

    def test_neveljavna_politika_je_izlocena(self):
        data = {("A0", "h3", "sni_black"): {"goodput_mbps": {"med": 10.0},
                                            "policy_ok_pct": {"med": 100.0}},
                ("B0", "h3", "sni_black"): {"goodput_mbps": {"med": 20.0},
                                            "policy_ok_pct": {"med": 49.0}}}
        got = plot.advantage(data, "goodput_mbps", "h3", "sni_black", True, "ratio",
                             ["A0", "B0"])
        assert got is None
