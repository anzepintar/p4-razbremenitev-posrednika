from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[2] / "common"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "content_block", COMMON / "proxy" / "content_block.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


content_block = load_module()


def rules_file(tmp_path, text):
    file = tmp_path / "content_rules.txt"
    file.write_text(text, encoding="utf-8")
    return file


class TestLoadRules:
    def test_utez_ime_in_filter(self, tmp_path):
        file = rules_file(tmp_path, '60 geslo ~bs "vpisite geslo"\n40 obrazec ~bs "<form"\n')
        rules = content_block.load_rules(file)
        assert [(w, n) for w, n, _ in rules] == [(60, "geslo"), (40, "obrazec")]

    def test_opombe_in_prazne_vrstice(self, tmp_path):
        file = rules_file(tmp_path, "# opomba\n\n100 test ~bs x\n")
        assert len(content_block.load_rules(file)) == 1

    def test_manjkajoc_pravilnik_je_napaka(self, tmp_path):
        with pytest.raises(content_block.RuleError, match="pravilnika ni"):
            content_block.load_rules(tmp_path / "ni.txt")

    def test_prazen_pravilnik_je_napaka(self, tmp_path):
        with pytest.raises(content_block.RuleError, match="nobenega pravila"):
            content_block.load_rules(rules_file(tmp_path, "# same opombe\n"))

    def test_pokvarjena_vrstica_pove_stevilko(self, tmp_path):
        file = rules_file(tmp_path, "100 dobro ~bs x\nnekaj cudnega\n")
        with pytest.raises(content_block.RuleError, match=":2:"):
            content_block.load_rules(file)

    def test_neveljaven_filter_je_napaka(self, tmp_path):
        with pytest.raises(content_block.RuleError):
            content_block.load_rules(rules_file(tmp_path, "100 slabo ~~~ (\n"))


class TestPrag:

    def test_privzeti_prag(self):
        assert content_block.THRESHOLD == 100

    def test_vsota_pod_pragom_ne_blokira(self):
        matched = [(60, "geslo"), (30, "obrazec")]
        assert sum(w for w, _ in matched) < content_block.THRESHOLD

    def test_vsota_na_pragu_blokira(self):
        matched = [(60, "geslo"), (40, "obrazec")]
        assert sum(w for w, _ in matched) >= content_block.THRESHOLD


class TestBlockPage:
    def test_stran_je_slovenska_in_pravilno_kodirana(self):
        assert b"Blokirano" in content_block.BLOCK_PAGE
        assert b'charset="utf-8"' in content_block.BLOCK_PAGE
        assert b'lang="sl"' in content_block.BLOCK_PAGE
        content_block.BLOCK_PAGE.decode("utf-8")
