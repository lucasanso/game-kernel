"""Desktop application (native/app, Qt 6 C++): QtTest suite driven by pytest.

Real signed packages and a trusted key are produced with the Python publisher code, the C++ UI
installs/rolls them back through native/updates, and helper-backed pages talk to the real Python
helper. Screenshots of every page are written to build/native-app/screenshots for inspection.
"""

from __future__ import annotations

import json
import re
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gamekernel.updates import package as pkg
from tests.native.native_build import BUILD_ROOT, ROOT, build_project, run_qtest

YARA_RULE = '''rule GK_UI_Test
{
    meta:
        description = "Regra de teste da interface"
        category = "test_file"
        severity = "INFO"
        author = "Game Kernel tests"
    strings:
        $a = "GAMEKERNEL-UI-TEST"
    condition:
        $a
}
'''


def _components(base, tag: str) -> dict:
    yara_dir, ioc_dir = base / f"yara-{tag}", base / f"ioc-{tag}"
    yara_dir.mkdir(parents=True)
    ioc_dir.mkdir(parents=True)
    (yara_dir / "ui.yar").write_text(YARA_RULE.replace("GK_UI_Test", f"GK_UI_Test_{tag}"), encoding="utf-8")
    (ioc_dir / "local.json").write_text(json.dumps({"format": "gamekernel-ioc", "version": tag, "entries": [
        {"sha256": "d" * 64, "verdict": "bad", "name": "Teste", "category": "trojan", "severity": "HIGH"}]}),
        encoding="utf-8")
    return {"yara": yara_dir, "ioc": ioc_dir}


def test_desktop_application(isolated_data_dir, tmp_path):
    exe = build_project("native-app", ROOT / "native" / "app", "gk_app_tests")
    private = Ed25519PrivateKey.generate()
    key = tmp_path / "release.pub"
    key.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo))
    packages = {}
    for name, version in (("V0", "2026.11.10.1"), ("V1", "2026.11.12.1"), ("V2", "2026.11.13.1")):
        out = tmp_path / f"{name}.gkpkg"
        pkg.build_package(out, private, version, _components(tmp_path, name), publisher="Equipe de testes")
        packages[f"GK_TEST_PKG_{name}"] = str(out)
    shots = BUILD_ROOT / "native-app" / "screenshots"
    code, report = run_qtest(exe, {"GK_PYTHON": sys.executable, "GK_REPO": str(ROOT), "GK_TEST_KEY": str(key),
                                   "GK_SCREENSHOT_DIR": str(shots), "GAMEKERNEL_DATA_DIR": str(isolated_data_dir),
                                   **packages}, timeout=900)
    totals = re.search(r"Totals: (\d+) passed, (\d+) failed, (\d+) skipped", report)
    assert code == 0 and totals, report
    passed, failed, skipped = map(int, totals.groups())
    assert failed == 0 and skipped == 0, report
    assert passed >= 10, report
    assert sorted(p.name for p in shots.glob("*.png")) == ["01-atualizacoes.png", "02-sandbox.png", "03-privacidade.png"]
