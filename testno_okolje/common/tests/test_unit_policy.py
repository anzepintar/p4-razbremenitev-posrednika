import sys

import pytest

from conftest import ROOT

sys.path.insert(0, str(ROOT / "controller"))

import controller as controller_mod  # noqa: E402

LEVELS = ["high", "medium", "low"]
MITM = {"high": "direct", "medium": "direct", "low": "via_mitm"}
FULL = {"high": "mirror", "medium": "mirror", "low": "via_mitm"}
POLICY = {"trust_levels": LEVELS, "policy": {"mitm": MITM}}
CLIENTS = [
    {"id": "c1", "src_ip": "10.0.1.10", "trust": "high", "profile": "office"},
    {"id": "c3", "src_ip": "10.0.1.12", "trust": "low", "profile": "suspicious"},
]


@pytest.fixture
def policy_file(write_scenario):
    return write_scenario(
        {**POLICY, "clients": CLIENTS, "testset": {"ips": ["10.0.2.10", "10.0.2.11"]}}
    )


def build(mapping, clients, servers=None, levels=LEVELS):
    log = type("NoLog", (), {"write": lambda self, **row: None})()
    return controller_mod.Controller(
        mapping, clients, controller_mod.Steering(None), log, "mitm", servers, levels
    )


def test_load_policy_reads_mapping_clients_servers_and_levels(policy_file):
    policy = controller_mod.load_policy(policy_file, "mitm")
    assert policy.mapping["low"] == "via_mitm"
    assert policy.clients == {"10.0.1.10": "high", "10.0.1.12": "low"}
    assert policy.servers == ["10.0.2.10", "10.0.2.11"]
    assert policy.levels == LEVELS


@pytest.mark.parametrize(
    "name,raw,expected",
    [
        ("ni_je", {**POLICY, "clients": CLIENTS}, "mitm"),
        ("mitm", {"policy": {"mitm": {"high": "teleport"}}, "clients": []}, "teleport"),
        ("mitm", {"policy": {"mitm": {"high": "direct"}}, "clients": CLIENTS}, "low"),
        ("mitm", {"trust_levels": ["high"], "policy": {"mitm": MITM}, "clients": CLIENTS},
         "trust_levels"),
    ],
    ids=["neznana politika", "neznana akcija", "zaupanje brez akcije", "zaupanje izven lestvice"],
)
def test_invalid_policy_is_rejected(write_scenario, name, raw, expected):
    with pytest.raises(controller_mod.PolicyError, match=expected):
        controller_mod.load_policy(write_scenario(raw), name)


def test_bootstrap_applies_one_entry_per_client():
    controller = build(MITM, {"10.0.1.10": "high", "10.0.1.12": "low"}, ["10.0.2.10"])
    controller.bootstrap()
    assert controller.steering.entries == {"1:10.0.1.10": "direct", "1:10.0.1.12": "via_mitm"}


def test_mirror_policy_also_covers_the_server_direction():
    controller = build(FULL, {"10.0.1.10": "high"}, ["10.0.2.10", "10.0.2.11"])
    controller.bootstrap()
    assert controller.steering.entries == {
        "1:10.0.1.10": "mirror",
        "2:10.0.2.10": "mirror",
        "2:10.0.2.11": "mirror",
    }


def test_decide_marks_only_the_proxied_path_as_inspected():
    controller = build(MITM, {"10.0.1.10": "high", "10.0.1.12": "low"})
    assert controller.decide("10.0.1.10")["action"] == "direct"
    assert controller.decide("10.0.1.12")["action"] == "inspect"
    # Nevednost ne sme pomeniti obida.
    assert controller.decide("10.9.9.9")["action"] == "inspect"


def test_alert_demotes_medium_onto_the_proxy():
    controller = build(FULL, {"10.0.1.11": "medium"})
    controller.bootstrap()
    result = controller.alert('{"src_ip": "10.0.1.11"}')
    assert (result["trust_after"], result["action_after"], result["changed"]) == \
        ("low", "via_mitm", True)
    assert controller.steering.entries["1:10.0.1.11"] == "via_mitm"


def test_high_needs_two_alerts_to_reach_the_proxy():
    controller = build(FULL, {"10.0.1.10": "high"})
    controller.bootstrap()

    first = controller.alert('{"src_ip": "10.0.1.10"}')
    assert (first["trust_after"], first["changed"]) == ("medium", False)
    assert controller.steering.entries["1:10.0.1.10"] == "mirror"

    second = controller.alert('{"src_ip": "10.0.1.10"}')
    assert (second["trust_after"], second["changed"]) == ("low", True)
    assert controller.steering.entries["1:10.0.1.10"] == "via_mitm"


def test_bottom_of_the_ladder_stays_put():
    controller = build(FULL, {"10.0.1.12": "low"})
    controller.bootstrap()
    result = controller.alert('{"src_ip": "10.0.1.12"}')
    assert (result["trust_after"], result["changed"]) == ("low", False)


def test_alert_for_unknown_source_changes_nothing():
    controller = build(FULL, {"10.0.1.10": "high"})
    result = controller.alert('{"src_ip": "10.9.9.9"}')
    assert result["changed"] is False
    assert controller.clients == {"10.0.1.10": "high"}
