import dataclasses
import random

import pytest

from runner import __main__ as runner_main


class FixedDraw:
    def __init__(self, value: float) -> None:
        self.value = value

    def random(self) -> float:
        return self.value


def sequence(scenario, profile, seed, count=40):
    rng = random.Random(seed)
    return [runner_main.build_request(scenario, profile, rng) for _ in range(count)]


def with_fields(scenario, name, **changes):
    return dataclasses.replace(scenario.profiles[name], **changes)


@pytest.mark.parametrize(
    "draw,expected",
    [(0.0, "h2"), (0.5, "h2"), (0.699, "h2"), (0.7, "h3"), (0.999, "h3")],
)
def test_pick_protocol_boundary(draw, expected):
    """Kumulativna meja je pri 0.7, ne priblizno tam."""
    assert runner_main.pick_protocol(FixedDraw(draw), {"h2": 0.7, "h3": 0.3}) == expected


def test_same_seed_gives_identical_sequence(scenario):
    """Pogoj za primerjavo topologij: isti seed = isto zaporedje zahtev."""
    profile = scenario.profiles["office"]
    assert sequence(scenario, profile, 1234) == sequence(scenario, profile, 1234)


def test_share_one_fronts_every_request(scenario):
    legit = {s.domain for s in scenario.by_label("ben")}
    phishing = {s.domain for s in scenario.by_label("mal")}
    profile = with_fields(scenario, "suspicious", fronting_share=1.0)

    for request, domain, fronted in sequence(scenario, profile, 99):
        assert fronted
        assert request.targets[0].domain in legit, "SNI mora biti legitimna domena"
        assert request.host_header in phishing, ":authority mora biti phishing domena"
        assert request.host_header == domain
        assert request.targets[0].domain != request.host_header


def test_share_zero_never_fronts(scenario):
    profile = with_fields(scenario, "suspicious", fronting_share=0.0)
    for request, _, fronted in sequence(scenario, profile, 99):
        assert not fronted
        assert request.host_header is None
