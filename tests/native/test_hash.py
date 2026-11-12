"""C++ hashing (libsodium SHA-256 + own MD5) must match hashlib exactly."""

import hashlib
import os
import random

import pytest

SIZES = [0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 1000, 4096, (1 << 20) - 1, 1 << 20, (1 << 20) + 1,
         3 * (1 << 20) + 17]


def test_api_version(native):
    assert native.API_VERSION == 1
    assert native.CORE_VERSION


def test_md5_rfc1321_vectors(native):
    vectors = {
        b"": "d41d8cd98f00b204e9800998ecf8427e",
        b"a": "0cc175b9c0f1b6a831c399e269772661",
        b"abc": "900150983cd24fb0d6963f7d28e17f72",
        b"message digest": "f96b697d7cb7938d525a2f31aaf161d0",
        b"abcdefghijklmnopqrstuvwxyz": "c3fcd3d76192e4007dfb496cca67e13b",
        b"1234567890" * 8: "57edf4a22be3c955ac49da2e2107b67a",
    }
    for data, digest in vectors.items():
        assert native.md5_bytes(data) == digest


@pytest.mark.parametrize("size", SIZES)
def test_bytes_equivalence(native, size):
    data = random.Random(size).randbytes(size)
    assert native.sha256_bytes(data) == hashlib.sha256(data).hexdigest()
    assert native.md5_bytes(data) == hashlib.md5(data).hexdigest()


@pytest.mark.parametrize("size", SIZES)
def test_file_equivalence(native, tmp_path, size):
    path = tmp_path / f"f{size}.bin"
    data = random.Random(size * 7).randbytes(size)
    path.write_bytes(data)
    result = native.hash_file(path)
    assert result == {"sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(), "size": size}
    assert native.sha256_file(str(path)) == result["sha256"]
    assert native.hash_file(path, with_md5=False)["md5"] is None


def test_errors_are_translated(native, tmp_path):
    with pytest.raises(native.GkError) as info:
        native.hash_file(tmp_path / "missing.exe")
    assert info.value.args[0] == 1001
    with pytest.raises(native.GkError):
        native.hash_file(tmp_path)  # a directory is not a regular file


@pytest.mark.skipif(os.name == "nt", reason="FIFOs are POSIX-only")
def test_special_files_are_rejected_without_blocking(native, tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(native.GkError):
        native.hash_file(fifo)
