"""Publisher-side package builder and Python reference verifier."""

from __future__ import annotations

import os

import pytest

from gamekernel.updates import package as pkg


def test_roundtrip_and_extraction(keypair, components, tmp_path):
    private, _, keys = keypair
    path = tmp_path / "p.gkpkg"
    manifest = pkg.build_package(path, private, "2026.11.12.1", components, publisher="t", description="d")
    assert [f["path"] for f in manifest["files"]][0].startswith("clamav/")
    out = tmp_path / "out"
    info = pkg.verify_package(path, keys, extract_to=out)
    assert info.key_id == manifest["signing_key_id"]
    for f in manifest["files"]:
        assert (out / f["path"]).stat().st_size == f["size"]
    assert not list(tmp_path.glob(".gkpkg-*"))


@pytest.mark.parametrize("setup, message", [
    (lambda d: (d / "evil.exe").write_bytes(b"MZ"), "não permitido"),
    (lambda d: (d / "sub").mkdir(), "subpastas"),
    (lambda d: os.symlink(d / "gamekernel_test.yar", d / "link.yar"), "links simbólicos"),
])
def test_builder_refuses_unsafe_inputs(keypair, components, tmp_path, setup, message):
    private, _, _ = keypair
    if "links" in message and os.name == "nt":
        pytest.skip("symlink requer privilégio no Windows")
    setup(components["yara"])
    with pytest.raises(pkg.PackageError, match=message):
        pkg.build_package(tmp_path / "x.gkpkg", private, "2026.11.12.1", {"yara": components["yara"]}, publisher="t")
    assert not (tmp_path / "x.gkpkg").exists()


def test_builder_refuses_bad_versions_and_empty(keypair, components, tmp_path):
    private, _, _ = keypair
    with pytest.raises(pkg.PackageError):
        pkg.build_package(tmp_path / "x.gkpkg", private, "12.11.2026", components, publisher="t")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(pkg.PackageError, match="vazio"):
        pkg.build_package(tmp_path / "x.gkpkg", private, "2026.11.12.1", {"ioc": empty}, publisher="t")
    with pytest.raises(pkg.PackageError, match="desconhecidos"):
        pkg.build_package(tmp_path / "x.gkpkg", private, "2026.11.12.1", {"drivers": empty}, publisher="t")


def test_version_ordering():
    assert pkg.version_tuple("2026.11.12") < pkg.version_tuple("2026.11.12.1") < pkg.version_tuple("2026.11.13")
    assert pkg.version_tuple("2026.2.1") < pkg.version_tuple("2026.10.1")
    with pytest.raises(pkg.PackageError):
        pkg.version_tuple("2026.11.12\n")
