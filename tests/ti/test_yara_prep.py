"""YARA preparation: compile/lint in Python (yara-python) and agreement with the C++ installer
validator (libyara) on the same rule sets."""

from __future__ import annotations

import pytest

from gamekernel.ti import yara_prep
from tests.updates.conftest import YARA_RULE, run_gk_update

RULESETS = {
    "valid": {"a.yar": YARA_RULE},
    "two_files_same_rule_name": {"a.yar": YARA_RULE, "b.yar": YARA_RULE},
    "syntax_error": {"a.yar": "rule x { condition: }"},
    "include": {"a.yar": 'include "other.yar"\nrule x { condition: true }'},
    "undefined_identifier": {"a.yar": "rule x { condition: nope_var > 1 }"},
    "external_vars": {"a.yar": 'rule x { condition: extension == ".exe" and filepath != "" }'},
    "pe_module": {"a.yar": 'import "pe"\nrule x { condition: pe.number_of_sections > 0 }'},
    "empty_file": {"a.yar": "// sem regras\n"},
    "wrong_extension": {"a.txt": YARA_RULE},
}


@pytest.mark.parametrize("name", sorted(RULESETS))
def test_python_and_cpp_agree(gk_update, tmp_path, name):
    d = tmp_path / name
    d.mkdir()
    for fname, text in RULESETS[name].items():
        (d / fname).write_text(text, encoding="utf-8")
    py = yara_prep.check_rules_dir(d)
    code, cpp = run_gk_update(gk_update, "validate", "--component", "yara", "--dir", d)
    assert py.ok == cpp["ok"], (name, py.errors, cpp["messages"])
    if py.ok:
        assert py.rule_count == cpp["count"]


def test_metadata_lint(tmp_path):
    (tmp_path / "a.yar").write_text('rule bare { strings: $a = "x" condition: $a }\n'
                                    'rule badcat { meta: description = "d" category = "virus" severity = "HIGH" '
                                    'author = "a" condition: false }\n', encoding="utf-8")
    rep = yara_prep.check_rules_dir(tmp_path)
    assert not rep.ok and any("categoria desconhecida" in e for e in rep.errors)
    assert any("meta ausente" in w for w in rep.warnings)
    strict = yara_prep.check_rules_dir(tmp_path, strict_meta=True)
    assert any("meta ausente" in e for e in strict.errors)


def test_complete_metadata_has_no_warnings(tmp_path):
    (tmp_path / "a.yar").write_text(YARA_RULE, encoding="utf-8")
    rep = yara_prep.check_rules_dir(tmp_path)
    assert rep.ok and rep.warnings == [] and rep.rules[0]["category"] == "test_file"
