import os
from pathlib import Path

import pytest

from runner import scenario as scenario_mod

ROOT = Path(os.environ.get("TRAFFIC_ROOT", "/opt/traffic"))
if not (ROOT / "scenario.yml").is_file():
    ROOT = Path(__file__).resolve().parents[1]

CONFIG = ROOT / "scenario.yml"
TESTSET = ROOT / "server" / "testset"


@pytest.fixture(scope="session")
def testset() -> Path:
    if not TESTSET.is_dir():
        pytest.skip("nabora ni - pozeni build_testset.py")
    return TESTSET


@pytest.fixture(scope="session")
def scenario(testset) -> scenario_mod.Scenario:
    return scenario_mod.load(CONFIG, testset=testset)


@pytest.fixture
def scenario_dict(testset) -> dict:
    return {
        "testset": {"set": "osnovni", "path": str(testset), "ips": ["10.0.2.10", "10.0.2.11"]},
        "clients": [
            {"id": "c1", "src_ip": "10.0.1.10", "trust": "high", "profile": "office"},
        ],
        "profiles": {
            "office": {
                "protocols": {"h2": 0.7, "h3": 0.3},
                "labels": ["ben"],
                "rate": 2.0,
                "think_time": [0.1, 0.2],
            }
        },
        "run": {"duration": 5, "seed": 1, "out": "/tmp/out"},
    }


@pytest.fixture
def write_scenario(tmp_path):
    import yaml

    def _write(data: dict) -> Path:
        path = tmp_path / "scenario.yml"
        path.write_text(yaml.safe_dump(data), encoding="utf-8")
        return path

    return _write
