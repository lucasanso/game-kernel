"""Archive engine (libarchive, in memory): equivalence with Python's readers and anti-abuse limits."""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import lzma
import os
import random
import shutil
import subprocess
import tarfile
import zipfile

import pytest

FUZZ_ITERATIONS = int(os.environ.get("GK_FUZZ_ITERATIONS", "300"))
SEVEN_ZIP = shutil.which("7z") or shutil.which("7za") or shutil.which("7zz")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _zip(entries: dict[str, bytes], compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def _files(result: dict) -> dict[str, str]:
    return {m["path"]: m["sha256"] for m in result["members"] if not m["is_directory"] and m["sha256"] is not None}


SAMPLE = {
    "readme.txt": b"Game Kernel test\n" * 10,
    "bin/game.exe": b"MZ" + random.Random(1).randbytes(5000),
    "data/level1.pak": random.Random(2).randbytes(20000),
    "acentuação/arquivo ç.txt": "conteúdo".encode(),
    "empty.bin": b"",
}


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2,
                                         zipfile.ZIP_LZMA])
def test_zip_equivalence(native, compression):
    data = _zip(SAMPLE, compression)
    result = native.archive_walk(data)
    assert result["complete"] and not result["errors"], result["errors"]
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        expected = {i.filename: _sha(z.read(i)) for i in z.infolist()}
    assert _files(result) == expected


@pytest.mark.parametrize("mode", ["w", "w:gz", "w:bz2", "w:xz"])
def test_tar_equivalence(native, mode):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as t:
        for name, data in SAMPLE.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    result = native.archive_walk(buf.getvalue())
    assert result["complete"], result["errors"]
    assert _files(result) == {k: _sha(v) for k, v in SAMPLE.items()}


@pytest.mark.parametrize("compress", [gzip.compress, bz2.compress, lzma.compress])
def test_single_stream_compression(native, compress):
    payload = b"MZ" + random.Random(3).randbytes(3000)
    result = native.archive_walk(compress(payload))
    assert result["complete"] and result["format"].startswith("raw")
    assert [m["sha256"] for m in result["members"]] == [_sha(payload)]


def test_iso9660(native, tmp_path):
    pycdlib = pytest.importorskip("pycdlib")
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3)
    content = b"MZ" + b"\x90" * 1000
    iso.add_fp(io.BytesIO(content), len(content), "/SETUP.EXE;1", joliet_path="/setup.exe")
    out = io.BytesIO()
    iso.write_fp(out)
    iso.close()
    result = native.archive_walk(out.getvalue())
    assert "9660" in result["format"]
    assert _sha(content) in _files(result).values()


@pytest.mark.skipif(SEVEN_ZIP is None, reason="7-Zip não disponível para gerar amostras")
def test_7z_plain_and_encrypted(native, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "crack.dll").write_bytes(b"MZ" + random.Random(4).randbytes(4000))
    plain = tmp_path / "plain.7z"
    subprocess.run([SEVEN_ZIP, "a", "-bd", str(plain), str(src / "crack.dll")], check=True, capture_output=True)
    result = native.archive_walk(plain.read_bytes())
    assert result["format"] == "7-Zip" and result["complete"]
    assert _files(result) == {"crack.dll": _sha((src / "crack.dll").read_bytes())}
    enc_zip = tmp_path / "enc.zip"
    subprocess.run([SEVEN_ZIP, "a", "-bd", "-tzip", "-pinfected", str(enc_zip), str(src / "crack.dll")], check=True,
                   capture_output=True)
    result = native.archive_walk(enc_zip.read_bytes())
    member = result["members"][0]
    assert result["encrypted_entries"] and member["encrypted"] and member["sha256"] is None
    assert "encrypted" in member["anomalies"]


def test_nested_archives_and_depth_limit(native):
    payload = b"MZ" + b"\x01" * 500
    data = _zip({"final.exe": payload})
    for level in range(6):
        data = _zip({f"level{level}.zip": data})
    result = native.archive_walk(data, {"max_depth": 3})
    assert "depth_limit" in result["anomalies"] and not result["complete"]
    assert max(m["depth"] for m in result["members"]) == 3
    deep = native.archive_walk(data, {"max_depth": 10})
    assert deep["complete"]
    exe = [m for m in deep["members"] if m["name"] == "final.exe"][0]
    assert exe["depth"] == 6 and exe["sha256"] == _sha(payload)
    assert exe["path"].count("::") == 6


def test_decompression_bomb_is_stopped(native):
    bomb = _zip({"zeros.bin": b"\0" * (64 << 20)})
    assert len(bomb) < 200_000
    result = native.archive_walk(bomb, {"ratio_min_bytes": 4 << 20, "max_ratio": 100})
    assert "decompression_bomb" in result["anomalies"] and not result["complete"]
    assert result["total_bytes"] < 16 << 20


def test_total_and_member_limits(native):
    rng = random.Random(5)
    many = _zip({f"f{i}.bin": rng.randbytes(1 << 20) for i in range(5)}, zipfile.ZIP_STORED)
    total = native.archive_walk(many, {"max_total_bytes": 3 << 20})
    assert "total_limit" in total["anomalies"] and total["total_bytes"] <= (3 << 20) + 65536
    big = rng.randbytes(3 << 20)
    member = native.archive_walk(_zip({"big.bin": big}), {"max_member_bytes": 1 << 20})["members"][0]
    assert "member_too_large" in member["anomalies"] and not member["complete"]
    assert member["bytes_read"] == 1 << 20 and member["sha256"] == _sha(big[: 1 << 20])
    crowded = native.archive_walk(_zip({f"n{i}.txt": b"x" for i in range(300)}), {"max_members": 100})
    assert "too_many_members" in crowded["anomalies"]


def test_suspicious_member_names_and_links(native):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../../Windows/System32/evil.dll", b"MZ")
        z.writestr("/etc/cron.d/x", b"x")
        z.writestr("C:\\Users\\Public\\run.bat", b"@echo off")
        link = zipfile.ZipInfo("shortcut")
        link.external_attr = (0o120777 << 16)
        link.create_system = 3
        z.writestr(link, "/etc/passwd")
    by_name = {m["name"]: m for m in native.archive_walk(buf.getvalue())["members"]}
    assert "path_traversal" in by_name["../../Windows/System32/evil.dll"]["anomalies"]
    assert "absolute_path" in by_name["/etc/cron.d/x"]["anomalies"]
    # libarchive normalises backslashes in ZIP names; the drive prefix is still recognised as absolute.
    assert "absolute_path" in by_name["C:/Users/Public/run.bat"]["anomalies"]
    link_member = by_name["shortcut"]
    assert link_member["is_symlink"] and link_member["sha256"] is None and "symlink" in link_member["anomalies"]


def test_self_extracting_layout_is_read(native):
    stub = b"MZ" + b"\0" * 0x3A + b"\x80\0\0\0" + b"\0" * 0x40 + b"PE\0\0" + b"\0" * 400
    result = native.archive_walk(stub + _zip(SAMPLE))
    assert _files(result) == {k: _sha(v) for k, v in SAMPLE.items()}


def test_corrupt_inputs(native):
    good = _zip(SAMPLE, zipfile.ZIP_DEFLATED)
    for broken in (good[: len(good) // 2], b"PK\x03\x04garbage", random.Random(6).randbytes(5000), b""):
        result = native.archive_walk(broken)
        assert not result["complete"] or not result["members"]
    flipped = bytearray(_zip({"a.bin": random.Random(7).randbytes(50000)}))
    flipped[2000] ^= 0xFF  # damage deflate data -> CRC / data error
    result = native.archive_walk(bytes(flipped))
    assert not result["complete"] and result["errors"]
    assert native.archive_recognised(good) and not native.archive_recognised(b"just text")


def test_mutation_fuzzing(native):
    rng = random.Random(int(os.environ.get("GK_FUZZ_SEED", "11")))
    seeds = [_zip(SAMPLE), _zip(SAMPLE, zipfile.ZIP_BZIP2), gzip.compress(b"x" * 5000)]
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:xz") as t:
        info = tarfile.TarInfo("a.exe")
        info.size = 4
        t.addfile(info, io.BytesIO(b"MZxx"))
    seeds.append(tar_buf.getvalue())
    for _ in range(FUZZ_ITERATIONS):
        sample = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 12)):
            if sample:
                sample[rng.randrange(len(sample))] = rng.randrange(256)
        if rng.random() < 0.2:
            sample = sample[: rng.randrange(len(sample) + 1)]
        native.archive_walk(bytes(sample), {"max_total_bytes": 64 << 20})
