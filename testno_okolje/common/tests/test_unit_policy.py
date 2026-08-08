import sys

import pytest

from conftest import ROOT

sys.path.insert(0, str(ROOT / "controller"))

import controller as controller_mod  # noqa: E402

POLICY = {"policy": {"mitm": {"high": "direct", "medium": "direct", "low": "via_mitm"}}}
CLIENTS = [
    {"id": "c1", "src_ip": "10.0.1.10", "trust": "high", "profile": "office"},
    {"id": "c3", "src_ip": "10.0.1.12", "trust": "low", "profile": "suspicious"},
]


@pytest.fixture
def policy_file(write_scenario):
    return write_scenario(
        {**POLICY, "clients": CLIENTS, "testset": {"ips": ["10.0.2.10", "10.0.2.11"]}}
    )


def test_server_addresses_come_from_testset(policy_file):
    _, _, servers = controller_mod.load_policy(policy_file, "mitm")
    assert servers == ["10.0.2.10", "10.0.2.11"]


def build(mapping, clients, servers=None):
    log = type("NoLog", (), {"write": lambda self, **row: None})()
    return controller_mod.Controller(
        mapping, clients, controller_mod.Steering(None), log, "mitm", servers
    )


def test_loads_mapping_and_clients(policy_file):
    mapping, clients, _ = controller_mod.load_policy(policy_file, "mitm")
    assert mapping["low"] == "via_mitm"
    assert clients == {"10.0.1.10": "high", "10.0.1.12": "low"}


def test_unknown_policy_name(policy_file):
    with pytest.raises(controller_mod.PolicyError, match="mitm"):
        controller_mod.load_policy(policy_file, "ni_je")


def test_unknown_action_is_rejected(write_scenario):
    path = write_scenario({"policy": {"mitm": {"high": "teleport"}}, "clients": []})
    with pytest.raises(controller_mod.PolicyError, match="teleport"):
        controller_mod.load_policy(path, "mitm")


def test_trust_without_mapping_is_rejected(write_scenario):
    path = write_scenario({"policy": {"mitm": {"high": "direct"}}, "clients": CLIENTS})
    with pytest.raises(controller_mod.PolicyError, match="low"):
        controller_mod.load_policy(path, "mitm")


def test_bootstrap_applies_one_entry_per_client():
    controller = build(POLICY["policy"]["mitm"], {"10.0.1.10": "high", "10.0.1.12": "low"})
    controller.bootstrap()
    assert controller.steering.entries == {"1:10.0.1.10": "direct", "1:10.0.1.12": "via_mitm"}


def test_mirror_policy_also_covers_the_server_direction():
    controller = build({"high": "mirror"}, {"10.0.1.10": "high"}, ["10.0.2.10", "10.0.2.11"])
    controller.bootstrap()
    assert controller.steering.entries == {
        "1:10.0.1.10": "mirror",
        "2:10.0.2.10": "mirror",
        "2:10.0.2.11": "mirror",
    }


def test_without_mirror_the_server_direction_stays_empty():
    controller = build(POLICY["policy"]["mitm"], {"10.0.1.12": "low"}, ["10.0.2.10"])
    controller.bootstrap()
    assert controller.steering.entries == {"1:10.0.1.12": "via_mitm"}


def test_decide_maps_via_mitm_to_inspect():
    controller = build(POLICY["policy"]["mitm"], {"10.0.1.10": "high", "10.0.1.12": "low"})
    assert controller.decide("10.0.1.10")["action"] == "direct"
    assert controller.decide("10.0.1.12")["action"] == "inspect"


def test_unknown_source_is_inspected():
    controller = build(POLICY["policy"]["mitm"], {"10.0.1.10": "high"})
    assert controller.decide("10.9.9.9")["action"] == "inspect"
