import re

import pytest

from conftest import ROOT

RULES = ROOT / "proxy" / "rules.txt"
LABEL_RULE = "testset_label"


def load_rules(path):
    rules = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            weight, name, pattern = line.split(maxsplit=2)
            rules.append((int(weight), name, re.compile(pattern, re.IGNORECASE)))
    return rules


@pytest.fixture(scope="module")
def rules():
    if not RULES.is_file():
        pytest.skip(f"pravilnika ni v {RULES}")
    return load_rules(RULES)


def test_label_rule_separates_the_set(rules, scenario):
    label = next(rx for _, name, rx in rules if name == LABEL_RULE)
    for site in scenario.sites.values():
        html = scenario.page_file(site.domain).read_text(encoding="utf-8", errors="replace")
        assert bool(label.search(html)) is (site.label == "mal"), site.domain
