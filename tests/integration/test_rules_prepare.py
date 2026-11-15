"""YARA preparation: compile/lint in Python (yara-python) and agreement with the C++ installer
validators on the same rule sets — the development build of cpp/updates (libyara directly) and the product
build, which delegates to the core (gk::yara::validate_rules_dir)."""

from __future__ import annotations

import pytest

from gamekernel.rules import prepare as yara_prep
from .conftest import YARA_RULE, run_gk_update
from .native_build import build_root_target

RULESETS = {
    "valid": {"a.yar": YARA_RULE},
    "two_files_same_rule_name": {"a.yar": YARA_RULE, "b.yar": YARA_RULE},
    "syntax_error": {"a.yar": "rule x { condition: }"},
    "include": {"a.yar": 'include "other.yar"\nrule x { condition: true }'},
    "undefined_identifier": {"a.yar": "rule x { condition: nope_var > 1 }"},
    "external_vars": {"a.yar": 'rule x { meta: category = "test_file" severity = "INFO" '
                               'condition: extension == ".exe" and filepath != "" }'},
    "pe_module": {"a.yar": 'import "pe"\nrule x { meta: category = "test_file" severity = "INFO" '
                           'condition: pe.number_of_sections > 0 }'},
    "empty_file": {"a.yar": "// sem regras\n"},
    "wrong_extension": {"a.txt": YARA_RULE},
}


@pytest.fixture(scope="module")
def gk_update_product():
    """gk-update as shipped: built from the repository root, validating YARA with the core."""
    return build_root_target("gk-update")


@pytest.mark.parametrize("build", ["development", "product"])
@pytest.mark.parametrize("name", sorted(RULESETS))
def test_python_and_cpp_agree(gk_update, gk_update_product, tmp_path, name, build):
    tool = gk_update if build == "development" else gk_update_product
    d = tmp_path / name
    d.mkdir()
    for fname, text in RULESETS[name].items():
        (d / fname).write_text(text, encoding="utf-8")
    py = yara_prep.check_rules_dir(d)
    code, cpp = run_gk_update(tool, "validate", "--component", "yara", "--dir", d)
    assert py.ok == cpp["ok"], (name, py.errors, cpp["messages"])
    if py.ok:
        assert py.rule_count == cpp["count"]


def test_metadata_lint(tmp_path):
    (tmp_path / "a.yar").write_text('rule bare { strings: $a = "x" condition: $a }\n'
                                    'rule badcat { meta: description = "d" category = "virus" severity = "HIGH" '
                                    'author = "a" condition: false }\n', encoding="utf-8")
    rep = yara_prep.check_rules_dir(tmp_path)
    assert not rep.ok and any("categoria desconhecida" in e for e in rep.errors)
    # category/severity are mandatory (the core refuses rules without them); description/author only warn
    assert any("bare: meta obrigatória ausente: category, severity" in e for e in rep.errors)
    assert any("meta ausente: description, author" in w for w in rep.warnings)
    strict = yara_prep.check_rules_dir(tmp_path, strict_meta=True)
    assert any("meta ausente: description, author" in e for e in strict.errors)


def test_complete_metadata_has_no_warnings(tmp_path):
    (tmp_path / "a.yar").write_text(YARA_RULE, encoding="utf-8")
    rep = yara_prep.check_rules_dir(tmp_path)
    assert rep.ok and rep.warnings == [] and rep.rules[0]["category"] == "test_file"


# The publisher gate versus the core's validator (gk::yara::validate_rules_dir, the one the app will use
# before activating a package, WORK_SPLIT rev. 4 §3): the gate must never accept what the core refuses.
_META = 'meta: category = "test_file" severity = "INFO"'
CORE_POLICY = {
    # name: (rules, expected decision of the gate, the core and the shipped installer)
    "complete": ({"a.yar": f'rule a {{ {_META} strings: $a = "x" condition: $a }}'}, True),
    "missing_category_severity": ({"a.yar": 'rule a { strings: $a = "x" condition: $a }'}, False),
    "pe_is_signed": ({"a.yar": f'import "pe"\nrule a {{ {_META} condition: pe.is_signed }}'}, False),
    "pe_signatures_spaced": ({"a.yar": f'import "pe"\nrule a {{ {_META} condition: pe . number_of_signatures > 0 }}'},
                             False),
    "pe_signatures_in_comment": ({"a.yar": f'// pe.signatures\nrule a {{ {_META} condition: false }}'}, False),
    "pe_other_fields_ok": ({"a.yar": f'import "pe"\nrule a {{ {_META} condition: pe.number_of_sections > 0 }}'}, True),
    "include": ({"a.yar": f'include "x.yar"\nrule a {{ {_META} condition: false }}'}, False),
    "externals": ({"a.yar": f'rule a {{ {_META} condition: extension == ".exe" }}'}, True),
    "unknown_category": ({"a.yar": 'rule a { meta: category = "virus" severity = "INFO" condition: false }'}, False),
    "invalid_severity": ({"a.yar": 'rule a { meta: category = "test_file" severity = "extreme" condition: false }'},
                         False),
    "severity_any_case": ({"a.yar": 'rule a { meta: category = "test_file" severity = "high" condition: false }'}, True),
    "empty_category": ({"a.yar": 'rule a { meta: category = "" severity = "INFO" condition: false }'}, False),
    "no_rules": ({"a.yar": "// nada\n"}, False),
}


@pytest.mark.parametrize("name", sorted(CORE_POLICY))
def test_publisher_gate_is_never_more_permissive_than_the_core(native, tmp_path, name):
    rules, expected = CORE_POLICY[name]
    for fname, text in rules.items():
        (tmp_path / fname).write_text(text, encoding="utf-8")
    gate = yara_prep.check_rules_dir(tmp_path)
    core = native.yara_validate_dir(str(tmp_path))
    if gate.ok:
        assert core["ok"], (name, core["errors"])
    assert gate.ok is expected and core["ok"] is expected, (name, gate.errors, core["errors"])


@pytest.mark.parametrize("name", sorted(CORE_POLICY))
def test_shipped_installer_decides_like_the_core(gk_update_product, tmp_path, name):
    rules, expected = CORE_POLICY[name]
    for fname, text in rules.items():
        (tmp_path / fname).write_text(text, encoding="utf-8")
    code, out = run_gk_update(gk_update_product, "validate", "--component", "yara", "--dir", tmp_path)
    assert out["ok"] is expected and (code == 0) is expected, (name, out["messages"])
