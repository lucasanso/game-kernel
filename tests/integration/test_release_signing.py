"""Release signed outside CI (docs/RELEASE.md): the CI prepares the folder with the release *public* key, the
publisher signs the manifest on their own computer, the CI attaches the signature to that same folder.

Stand-in binaries, as in test_distribution.py; the installed signed product is tested on Windows by the CI job
release-final.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gamekernel import crypto_utils
from gamekernel.core import integrity
from tools import make_distribution as MD
from tools import release_sign as RS

from .test_distribution import _agent_a_check, parts  # noqa: F401  (fixture)


def _write_key_pair(tmp_path, key: Ed25519PrivateKey, password: bytes | None = b"senha-de-teste-123"):
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    private = tmp_path / "release.key"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))
    public = tmp_path / "release.pub"
    public.write_bytes(MD.public_pem(key.public_key()))
    return private, public


def _prepare(parts, public_key) -> dict:  # noqa: F811
    plan = MD.Plan(out=parts["tmp"] / "dist" / "release" / "GameKernel", app=parts["app"], bins=parts["bins"],
                   helper=parts["helper"], crt_dir=parts["crt"], deploy_qt=False, public_key=public_key)
    return MD.build(plan)


def test_prepared_release_ships_the_public_key_and_awaits_the_signature(parts):  # noqa: F811
    key = Ed25519PrivateKey.generate()
    summary = _prepare(parts, key.public_key())
    out = parts["tmp"] / "dist" / "release" / "GameKernel"
    assert summary["awaiting_signature"] and not summary["signed"]
    assert summary["key_id"] == crypto_utils.key_id(key.public_key())
    assert (out / MD.RELEASE_PUB).read_bytes() == MD.public_pem(key.public_key())
    assert (out / integrity.MANIFEST_NAME).is_file() and not (out / integrity.SIGNATURE_NAME).exists()
    assert MD.RELEASE_PUB in json.loads((out / integrity.MANIFEST_NAME).read_bytes())["files"]
    assert not any(p.suffix == ".key" for p in out.rglob("*"))          # no private material anywhere


def test_sign_then_attach_produces_a_verified_release(parts, tmp_path, monkeypatch):  # noqa: F811
    key = Ed25519PrivateKey.generate()
    private, public = _write_key_pair(tmp_path, key)
    _prepare(parts, key.public_key())
    out = parts["tmp"] / "dist" / "release" / "GameKernel"

    # What the publisher downloads: only the manifest (and the CI's preparation note).
    downloaded = tmp_path / "manifesto"
    downloaded.mkdir()
    (downloaded / integrity.MANIFEST_NAME).write_bytes((out / integrity.MANIFEST_NAME).read_bytes())
    (downloaded / RS.PREPARATION_NAME).write_text(json.dumps({"execucao": 123456789, "commit": "abc123"}))
    shown = {}
    record = RS.sign_manifest(downloaded / integrity.MANIFEST_NAME, private, b"senha-de-teste-123",
                              confirm=lambda s: shown.update(s) or True)
    assert shown["chave"] == crypto_utils.key_id(key.public_key()) and shown["arquivos"] > 5
    assert record["execucao"] == 123456789 and len(base64.b64decode(record["assinatura"])) == 64
    stored = json.loads((downloaded / RS.RECORD_NAME).read_text(encoding="utf-8"))
    assert stored["assinatura"] == record["assinatura"]
    assert (downloaded / integrity.SIGNATURE_NAME).read_bytes() == base64.b64decode(record["assinatura"])

    zip_path = parts["tmp"] / "final" / "GameKernel-portable.zip"
    result = RS.attach_signature(out, str(downloaded / RS.RECORD_NAME), expect_key=public, portable_zip=zip_path)
    assert result["chave"] == crypto_utils.key_id(key.public_key()) and zip_path.is_file()
    report = _agent_a_check(out, monkeypatch)                                  # Agent A's checker agrees
    assert report.ok and report.signature_valid and report.signer_key_id == result["chave"]
    assert MD.manifest_problems(out) == []


def test_signing_is_refused_with_another_key_or_a_wrong_password(parts, tmp_path):  # noqa: F811
    prepared_with = Ed25519PrivateKey.generate()
    _prepare(parts, prepared_with.public_key())
    manifest = parts["tmp"] / "dist" / "release" / "GameKernel" / integrity.MANIFEST_NAME
    other, _ = _write_key_pair(tmp_path, Ed25519PrivateKey.generate())
    with pytest.raises(RS.ReleaseError, match="não leva a chave pública"):
        RS.sign_manifest(manifest, other, b"senha-de-teste-123", confirm=lambda s: True)
    right_dir = tmp_path / "certa"
    right_dir.mkdir()
    right, _ = _write_key_pair(right_dir, prepared_with)
    with pytest.raises(RS.ReleaseError, match="senha errada"):
        RS.sign_manifest(manifest, right, b"outra-senha-qualquer", confirm=lambda s: True)
    with pytest.raises(RS.ReleaseError, match="cancelada"):
        RS.sign_manifest(manifest, right, b"senha-de-teste-123", confirm=lambda s: False)
    assert not manifest.with_name(integrity.SIGNATURE_NAME).exists()          # nothing signed


def test_attach_refuses_what_does_not_verify(parts, tmp_path):  # noqa: F811
    key = Ed25519PrivateKey.generate()
    _prepare(parts, key.public_key())
    out = parts["tmp"] / "dist" / "release" / "GameKernel"
    raw = (out / integrity.MANIFEST_NAME).read_bytes()
    forged = base64.b64encode(crypto_utils.sign(Ed25519PrivateKey.generate(), raw)).decode()
    with pytest.raises(RS.ReleaseError, match="assinatura do manifesto não confere"):
        RS.attach_signature(out, forged)
    assert not (out / integrity.SIGNATURE_NAME).exists()                       # a failed attach leaves no .sig
    with pytest.raises(RS.ReleaseError, match="base64"):
        RS.attach_signature(out, "não é base64!")
    with pytest.raises(RS.ReleaseError, match="64"):
        RS.attach_signature(out, base64.b64encode(b"curta").decode())
    good = base64.b64encode(crypto_utils.sign(key, raw)).decode()
    _, other_pub = _write_key_pair(tmp_path, Ed25519PrivateKey.generate())
    with pytest.raises(RS.ReleaseError, match="não a chave de release esperada"):
        RS.attach_signature(out, good, expect_key=other_pub)
    # The folder changed after the preparation (a binary replaced): the signature cannot finish it.
    (out / parts["app"].name).write_bytes(b"trocado")
    with pytest.raises(RS.ReleaseError, match="alterado"):
        RS.attach_signature(out, good)


def test_command_line_round_trip(parts, tmp_path, capsys):  # noqa: F811
    key = Ed25519PrivateKey.generate()
    private, public = _write_key_pair(tmp_path, key, password=None)
    _prepare(parts, key.public_key())
    out = parts["tmp"] / "dist" / "release" / "GameKernel"
    manifest = tmp_path / integrity.MANIFEST_NAME
    manifest.write_bytes((out / integrity.MANIFEST_NAME).read_bytes())
    assert RS.main(["sign", str(manifest), "--key", str(private), "--no-password", "--yes"]) == 0
    assert RS.main(["attach", str(out), "--signature", str(tmp_path / integrity.SIGNATURE_NAME),
                    "--expect-key", str(public)]) == 0
    assert RS.main(["attach", str(out), "--signature", "AAAA"]) == 1
    assert "erro:" in capsys.readouterr().err
    assert RS.main(["key-id", str(public)]) == 0
    assert capsys.readouterr().out.strip() == crypto_utils.key_id(key.public_key())


def test_distribution_cli_prepares_with_the_public_key_only(parts, tmp_path, capsys):  # noqa: F811
    key = Ed25519PrivateKey.generate()
    _, public = _write_key_pair(tmp_path, key)
    out = tmp_path / "pronta" / "GameKernel"
    args = ["--app", str(parts["app"]), "--helper", str(parts["helper"]), "--crt-dir", str(parts["crt"]),
            "--allow-missing-core", "--public-key", str(public), "--out", str(out)]
    for b in parts["bins"]:
        args += ["--bin", str(b)]
    monkey_deploy = MD._deploy_qt
    MD._deploy_qt = lambda *a, **k: None   # stand-in binaries: no windeployqt
    try:
        assert MD.main(args) == 0
        summary = json.loads(capsys.readouterr().out)
        assert summary["awaiting_signature"] and summary["key_id"] == crypto_utils.key_id(key.public_key())
        with pytest.raises(SystemExit):   # the portable ZIP only after the signature
            MD.main(args + ["--portable-zip", str(tmp_path / "x.zip")])
    finally:
        MD._deploy_qt = monkey_deploy


# ---------------------------------------------------------------------------- the repository itself
ROOT = Path(__file__).resolve().parents[2]
PEM_PRIVATE = re.compile(rb"-----BEGIN (?:ENCRYPTED |RSA |EC |OPENSSH )?PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{40,}")


def _tracked_files() -> list[Path]:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True, timeout=60).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git indisponível")
    return [ROOT / name.decode("utf-8") for name in out.split(b"\0") if name]


def test_no_private_key_in_the_repository():
    """installer/release/ holds public material only; a private key anywhere in the repository fails the build."""
    offenders = []
    for path in _tracked_files():
        if path.suffix.lower() in (".key", ".p12", ".pfx"):
            offenders.append(path.relative_to(ROOT).as_posix())
        elif path.is_file() and path.stat().st_size < 2 * 1024 * 1024 and PEM_PRIVATE.search(path.read_bytes()):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == [], f"material de chave privada no repositório: {offenders}"


def test_release_files_in_the_repository_are_consistent():
    """When the publisher's files are present, they must be what the CI job release-final expects."""
    pub_path = ROOT / "installer" / "release" / "release.pub"
    record_path = ROOT / "installer" / "release" / "assinatura.json"
    if not pub_path.exists():
        assert not record_path.exists(), "assinatura.json sem a chave pública release.pub"
        pytest.skip("nenhuma chave de release no repositório ainda")
    kid = crypto_utils.key_id(crypto_utils.load_public_key(pub_path.read_bytes()))
    if record_path.exists():
        record = json.loads(record_path.read_text(encoding="utf-8"))
        assert re.fullmatch(r"[0-9]{5,20}", str(record["execucao"])), record
        assert record["chave"] == kid, "assinatura.json feito com outra chave"
        assert len(base64.b64decode(record["assinatura"], validate=True)) == 64
