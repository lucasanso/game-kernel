"""Quarantine vault (.gkq) and its bookkeeping (database, events, audit chain).

The vault is exercised in-process through gk_native; the full flow (vault + database + audit) runs through
`gk-cli quarantine` in a subprocess, and the Python layer then reads what C++ wrote. Contents are generated
at test time; nothing is executed.
"""

from __future__ import annotations

import gc
import hashlib
import os
import random
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from gamekernel.database.db import Database

ROOT = Path(__file__).resolve().parents[2]
FUZZ_ITERATIONS = int(os.environ.get("GK_FUZZ_ITERATIONS", "300"))
INVALID_REQUEST, FILE_ACCESS, INVALID_FORMAT = -32600, 1001, 1005
MARKER = b"GK-PLAINTEXT-MARKER-"


def _content(size: int, seed: int = 0) -> bytes:
    body = random.Random(seed).randbytes(max(0, size - len(MARKER)))
    return (MARKER + body)[:size]


@pytest.fixture
def vault(native, tmp_path):
    return native.QuarantineVault.open(str(tmp_path / "vault"))


def _put(tmp_path: Path, name: str, data: bytes) -> Path:
    f = tmp_path / "game" / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(data)
    return f


def _quarantine(vault, path: Path, **kw) -> dict:
    pending = vault.prepare(str(path), **kw)
    meta = pending.metadata
    pending.commit()
    return meta


def _code(excinfo) -> int:
    return excinfo.value.args[0]


# ------------------------------------------------------------------------------------------ vault

@pytest.mark.parametrize("size", [0, 1, 4096, 1 << 20, (1 << 20) + 1, 3 * (1 << 20) + 12345])
def test_roundtrip(vault, tmp_path, size):
    data = _content(size, size)
    original = _put(tmp_path, "arquivo ç.exe", data)
    pending = vault.prepare(str(original), reason="teste", risk=4)
    meta = pending.metadata
    assert original.exists(), "the original stays until commit"
    assert meta["sha256"] == hashlib.sha256(data).hexdigest() and meta["size"] == size
    assert meta["original_path"] == str(original.resolve()) and meta["risk"] == 4 and meta["reason"] == "teste"
    pending.commit()
    assert not original.exists()
    stored = Path(vault.item_path(meta["id"])).read_bytes()
    assert stored[:4] == b"GKQ1" and (size < len(MARKER) or MARKER not in stored)   # content is encrypted
    assert vault.inspect(meta["id"]) == meta
    target = tmp_path / "restored" / "out.exe"
    assert vault.restore(meta["id"], str(target)) == meta
    assert target.read_bytes() == data
    assert not list(target.parent.glob(".*.gkrestore")), "no temporary file left behind"


def test_abort_keeps_the_original(vault, tmp_path):
    original = _put(tmp_path, "a.exe", _content(5000))
    pending = vault.prepare(str(original))
    item = Path(vault.item_path(pending.metadata["id"]))
    assert item.exists()
    pending.abort()
    assert original.exists() and not item.exists()
    # An uncommitted operation that is simply dropped is aborted too.
    pending = vault.prepare(str(original))
    item = Path(vault.item_path(pending.metadata["id"]))
    del pending
    gc.collect()
    assert original.exists() and not item.exists()


def test_changed_file_is_refused(vault, tmp_path):
    original = _put(tmp_path, "a.exe", _content(5000))
    with pytest.raises(Exception) as e:
        vault.prepare(str(original), expected_sha256="0" * 64)
    assert _code(e) == INVALID_REQUEST and "mudou" in e.value.args[1]
    assert original.exists()
    assert [p.name for p in Path(vault.dir).iterdir()] == ["vault.key"], "nothing left in the vault"
    # Upper-case hashes from other tools are accepted.
    meta = _quarantine(vault, original, expected_sha256=hashlib.sha256(_content(5000)).hexdigest().upper())
    assert meta["size"] == 5000


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_only_regular_files(vault, tmp_path):
    real = _put(tmp_path, "real.exe", b"x" * 10)
    link = tmp_path / "game" / "link.exe"
    link.symlink_to(real)
    for target in (link, tmp_path / "game"):
        with pytest.raises(Exception) as e:
            vault.prepare(str(target))
        assert _code(e) == FILE_ACCESS
    assert real.exists() and link.is_symlink()


def _items(vault, tmp_path, size=3 * (1 << 20) + 7):
    data = _content(size, 7)
    meta = _quarantine(vault, _put(tmp_path, "m.exe", data))
    return meta, Path(vault.item_path(meta["id"])), data


@pytest.mark.parametrize("damage", ["flip_content", "flip_prefix", "flip_header", "truncate", "append",
                                    "drop_final", "swap_chunks"])
def test_damaged_items_are_refused(vault, tmp_path, damage):
    meta, item, _ = _items(vault, tmp_path)
    raw = bytearray(item.read_bytes())
    first = 16 + 24                                       # prefix + secretstream header
    if damage == "flip_content":
        raw[len(raw) // 2] ^= 0x01
    elif damage == "flip_prefix":
        raw[5] ^= 0x01                                    # reserved byte: authenticated as associated data
    elif damage == "flip_header":
        raw[20] ^= 0x01
    elif damage == "truncate":
        raw = raw[:len(raw) - 100]
    elif damage == "append":
        raw += b"\0"
    else:
        blocks, pos = [], first
        while pos < len(raw):
            n = struct.unpack_from("<I", raw, pos)[0]
            blocks.append(bytes(raw[pos:pos + 4 + n]))
            pos += 4 + n
        if damage == "drop_final":
            blocks = blocks[:-1]
        else:
            blocks[0], blocks[1] = blocks[1], blocks[0]
        raw = raw[:first] + b"".join(blocks)
    item.write_bytes(bytes(raw))
    with pytest.raises(Exception) as e:
        vault.inspect(meta["id"])
    assert _code(e) == INVALID_FORMAT and "danificado" in e.value.args[1]
    target = tmp_path / "out" / "m.exe"
    with pytest.raises(Exception):
        vault.restore(meta["id"], str(target))
    assert not target.exists() and not list((tmp_path / "out").glob(".*"))


def test_every_byte_is_authenticated(vault, tmp_path):
    meta, item, _ = _items(vault, tmp_path, size=70_000)
    base = item.read_bytes()
    rng = random.Random(99)
    for _ in range(FUZZ_ITERATIONS):
        raw = bytearray(base)
        pos = rng.randrange(len(raw))
        raw[pos] ^= rng.randrange(1, 256)
        item.write_bytes(bytes(raw))
        with pytest.raises(Exception) as e:
            vault.inspect(meta["id"])
        assert _code(e) == INVALID_FORMAT, (pos, e.value.args)
    item.write_bytes(base)
    assert vault.inspect(meta["id"]) == meta


def test_key_is_persistent_and_items_need_it(native, vault, tmp_path):
    meta, item, data = _items(vault, tmp_path, size=10_000)
    again = native.QuarantineVault.open(vault.dir)
    assert again.key_id == vault.key_id and again.inspect(meta["id"]) == meta
    if os.name != "nt":
        assert (Path(vault.dir) / "vault.key").stat().st_mode & 0o077 == 0
        assert Path(vault.dir).stat().st_mode & 0o077 == 0
    other = native.QuarantineVault.open(str(tmp_path / "other"))
    assert other.key_id != vault.key_id
    shutil.copy(item, other.item_path(meta["id"]))
    with pytest.raises(Exception) as e:
        other.inspect(meta["id"])
    assert _code(e) == INVALID_FORMAT and "outra chave" in e.value.args[1]


def test_restore_never_overwrites_by_accident(vault, tmp_path):
    meta, _, data = _items(vault, tmp_path, size=2000)
    target = tmp_path / "game" / "m.exe"
    target.write_bytes(b"new file in place")
    with pytest.raises(Exception) as e:
        vault.restore(meta["id"], str(target))
    assert _code(e) == FILE_ACCESS and target.read_bytes() == b"new file in place"
    with pytest.raises(Exception):
        vault.restore(meta["id"], str(target), expected_sha256="1" * 64)     # database disagrees
    assert target.read_bytes() == b"new file in place"
    vault.restore(meta["id"], str(target), overwrite=True)
    assert target.read_bytes() == data


def test_verify_reports_ok_unknown_damaged_and_missing(vault, tmp_path):
    a, _, _ = _items(vault, tmp_path, size=100)
    b = _quarantine(vault, _put(tmp_path, "b.exe", b"bbb"))
    c = _quarantine(vault, _put(tmp_path, "c.exe", b"ccc"))
    raw = bytearray(Path(vault.item_path(c["id"])).read_bytes())
    raw[-1] ^= 1
    Path(vault.item_path(c["id"])).write_bytes(bytes(raw))
    missing = "f" * 32
    report = vault.verify([a["id"], c["id"], missing])
    assert report["ok"] == [a["id"]]
    assert [m["id"] for m in report["unknown"]] == [b["id"]] and report["unknown"][0]["sha256"] == hashlib.sha256(b"bbb").hexdigest()
    assert {d[0] for d in report["damaged"]} == {c["id"], missing}


def test_invalid_ids_are_rejected(vault):
    for bad in ("../vault", "x" * 32, "", "A" * 32):
        with pytest.raises(Exception) as e:
            vault.inspect(bad)
        assert _code(e) == INVALID_REQUEST


# ------------------------------------------------------------------------------------------ gk-cli + database

CLI_CANDIDATES = [ROOT / "build" / p / "cpp" / "cli" / ("gk-cli.exe" if os.name == "nt" else "gk-cli")
                  for p in ("linux-release", "linux-debug", "linux-asan", "windows-release/Release")]


@pytest.fixture(scope="module")
def cli():
    for c in CLI_CANDIDATES:
        if c.exists():
            return c
    if os.environ.get("GK_REQUIRE_CLI") == "1":
        pytest.fail("gk-cli não compilado")
    pytest.skip("gk-cli não compilado (requer Qt 6)")


def _q(cli, data: Path, *args):
    return subprocess.run([str(cli), "quarantine", *map(str, args), "--data-dir", str(data)],
                          capture_output=True, text=True, timeout=120)


def test_cli_full_cycle_is_recorded(cli, tmp_path):
    data = tmp_path / "data"
    payload = _content(200_000, 3)
    f = _put(tmp_path, "trojan ç.exe", payload)
    add = _q(cli, data, "add", f, "--expect-sha256", hashlib.sha256(payload).hexdigest(), "--reason", "detecção")
    assert add.returncode == 0, add.stderr
    item_id = add.stdout.strip()
    assert not f.exists() and (data / "quarantine" / f"{item_id}.gkq").exists()

    db = Database(data / "gamekernel.db")
    row = db.get_quarantine_item(item_id)
    assert row["status"] == "quarantined" and row["original_path"] == str(f.resolve())
    assert row["sha256"] == hashlib.sha256(payload).hexdigest() and row["size"] == len(payload)
    assert row["reason"] == "detecção" and row["stored_name"] == f"{item_id}.gkq" and row["meta"]["format"] == "gkq1"
    db.close()

    listed = _q(cli, data, "list")
    assert item_id in listed.stdout
    restore = _q(cli, data, "restore", item_id)
    assert restore.returncode == 0, restore.stderr
    assert f.read_bytes() == payload and not (data / "quarantine" / f"{item_id}.gkq").exists()

    f2 = _put(tmp_path, "dropper.exe", b"dropper")
    second = _q(cli, data, "add", f2).stdout.strip()
    delete = _q(cli, data, "delete", second)
    assert delete.returncode == 0, delete.stderr
    assert _q(cli, data, "restore", second).returncode == 2       # deleted items cannot come back

    db = Database(data / "gamekernel.db")
    assert db.get_quarantine_item(item_id)["status"] == "restored"
    assert db.get_quarantine_item(second)["status"] == "deleted"
    events = [(e["item_id"], e["action"]) for e in reversed(db.list_quarantine_events())]
    assert events == [(item_id, "quarantine"), (item_id, "restore"), (second, "quarantine"), (second, "delete")]
    assert db.verify_audit_chain() == (True, None)
    actions = [e["action"] for e in reversed(db.list_audit())]
    assert actions == ["quarantine", "restore", "quarantine", "delete"]


def test_cli_refuses_changed_file_and_conflicting_restore(cli, tmp_path):
    data = tmp_path / "data"
    f = _put(tmp_path, "a.exe", b"original")
    bad = _q(cli, data, "add", f, "--expect-sha256", "0" * 64)
    assert bad.returncode == 2 and "mudou" in bad.stderr and f.exists()
    item_id = _q(cli, data, "add", f).stdout.strip()
    f.write_bytes(b"user put something new here")
    conflict = _q(cli, data, "restore", item_id)
    assert conflict.returncode == 2 and "já existe" in conflict.stderr
    assert f.read_bytes() == b"user put something new here"
    other = tmp_path / "elsewhere" / "a.exe"
    assert _q(cli, data, "restore", item_id, "--to", other).returncode == 0
    assert other.read_bytes() == b"original"


def test_cli_verify_recovers_lost_database_and_flags_damage(cli, tmp_path):
    data = tmp_path / "data"
    ids = [_q(cli, data, "add", _put(tmp_path, f"f{i}.exe", bytes([i]) * 1000)).stdout.strip() for i in range(3)]
    for suffix in ("", "-wal", "-shm"):
        Path(str(data / "gamekernel.db") + suffix).unlink(missing_ok=True)
    verify = _q(cli, data, "verify", "--json", tmp_path / "v.json")
    assert verify.returncode == 0, verify.stderr
    assert "recuperados: 3" in verify.stdout
    listed = _q(cli, data, "list").stdout
    assert all(i in listed for i in ids)
    assert _q(cli, data, "restore", ids[0]).returncode == 0
    assert (tmp_path / "game" / "f0.exe").read_bytes() == b"\0" * 1000

    item = data / "quarantine" / f"{ids[1]}.gkq"
    raw = bytearray(item.read_bytes())
    raw[60] ^= 1
    item.write_bytes(bytes(raw))
    damaged = _q(cli, data, "verify")
    assert damaged.returncode == 5 and ids[1] in damaged.stdout
