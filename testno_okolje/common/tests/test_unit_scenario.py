import pytest

from runner import scenario as scenario_mod
from runner.scenario import ScenarioError


def test_missing_set_is_rejected(scenario_dict, write_scenario):
    scenario_dict["testset"]["set"] = "ni-me"
    with pytest.raises(ScenarioError, match="nabora 'ni-me' ni"):
        scenario_mod.load(write_scenario(scenario_dict))


def test_label_absent_from_testset_is_rejected(scenario_dict, write_scenario):
    scenario_dict["profiles"]["office"]["labels"] = ["ni-me"]
    with pytest.raises(ScenarioError, match="ni oznak"):
        scenario_mod.load(write_scenario(scenario_dict))


def test_unknown_protocol_is_rejected(scenario_dict, write_scenario):
    scenario_dict["profiles"]["office"]["protocols"] = {"h2": 0.5, "h1": 0.5}
    with pytest.raises(ScenarioError, match="neznani protokoli"):
        scenario_mod.load(write_scenario(scenario_dict))


def test_unknown_profile_is_rejected(scenario_dict, write_scenario):
    scenario_dict["clients"][0]["profile"] = "ni-me"
    with pytest.raises(ScenarioError, match="neznan profil"):
        scenario_mod.load(write_scenario(scenario_dict))
