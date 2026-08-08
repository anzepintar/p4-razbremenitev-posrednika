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


def test_every_phishing_domain_gets_one_rule(rules, scenario):
    assert sorted(m["domain"] for m in rules) == sorted(s.domain for s in scenario.by_label("mal"))


def test_no_rule_for_legitimate_domains(rules, scenario):
    legit = {s.domain for s in scenario.by_label("ben")}
    assert not legit & {m["domain"] for m in rules}


def test_sids_are_unique(rules):
    sids = [m["sid"] for m in rules]
    assert len(set(sids)) == len(sids)


def test_bsize_matches_domain_length(rules):
    assert all(int(m["size"]) == len(m["domain"]) for m in rules)
