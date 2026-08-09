import re
import sys

import pytest

from conftest import ROOT

sys.path.insert(0, str(ROOT / "ids"))

import gen_rules  # noqa: E402

RULE = re.compile(r'content:"(?P<domain>[^"]+)"; bsize:(?P<size>\d+); sid:(?P<sid>\d+);')


@pytest.fixture(scope="module")
def rules(scenario):
    return [RULE.search(line) for line in gen_rules.render(scenario).splitlines()
            if line.startswith("alert")]


def test_one_rule_per_phishing_domain(rules, scenario):
    assert sorted(m["domain"] for m in rules) == sorted(s.domain for s in scenario.by_label("mal"))
    assert len({m["sid"] for m in rules}) == len(rules), "podvojen sid je napaka za Suricato"
    assert all(int(m["size"]) == len(m["domain"]) for m in rules)
