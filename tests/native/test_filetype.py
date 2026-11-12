"""Equivalence of the C++ file type identification with the Python reference (core/filetypes.py)."""

import random
import struct

import pytest

from gamekernel.core import filetypes as py_ft

EXTENSIONS = ["", ".exe", ".dll", ".sys", ".pak", ".txt", ".zip", ".jar", ".class", ".msi", ".doc", ".iso", ".lnk",
              ".url", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".reg", ".bin", ".dat", ".7z", ".rar", ".ini", ".json",
              ".msstyles", ".PNG", ".EXE", ".Ps1"]


def _pe(dll=False, subsystem=3, dotnet=False, magic=0x20B, e_lfanew=0x80, size=1024, sig=b"PE\0\0"):
    data = bytearray(size)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    if e_lfanew + 24 <= size:
        data[e_lfanew:e_lfanew + 4] = sig
        struct.pack_into("<H", data, e_lfanew + 22, 0x2022 if dll else 0x0022)
        opt = e_lfanew + 24
        if opt + 2 <= size:
            struct.pack_into("<H", data, opt, magic)
        if opt + 70 <= size:
            struct.pack_into("<H", data, opt + 68, subsystem)
        clr = opt + (96 if magic == 0x10B else 112) + 14 * 8
        if dotnet and clr + 8 <= size:
            struct.pack_into("<I", data, clr, 0x2000)
    return bytes(data)


def _corpus():
    headers = [
        _pe(), _pe(dll=True), _pe(subsystem=1), _pe(dotnet=True), _pe(dotnet=True, dll=True), _pe(magic=0x10B),
        _pe(magic=0x10B, dotnet=True), _pe(e_lfanew=0), _pe(e_lfanew=5000), _pe(sig=b"NE\0\0"), _pe(size=0x40),
        _pe(size=0x98), _pe(e_lfanew=0x80, size=0x80 + 24 + 50), b"MZ", b"MZ" + b"\0" * 62,
        b"\x7fELF" + b"\0" * 60, b"\xcf\xfa\xed\xfe" + b"\0" * 10, b"\xca\xfe\xba\xbe" + b"\0" * 10,
        b"PK\x03\x04" + b"\0" * 40, b"PK\x03\x04" + b"x" * 100 + b"META-INF/MANIFEST.MF", b"PK\x05\x06" + b"\0" * 18,
        b"PK\x03\x04" + b"x" * 600 + b"META-INF/", b"Rar!\x1a\x07\x01\x00", b"Rar!\x1a\x07\x00", b"7z\xbc\xaf\x27\x1c\0\x04",
        b"\x1f\x8b\x08", b"BZh91AY", b"\xfd7zXZ\x00\x00", b"\x28\xb5\x2f\xfd\x24", b"MSCF\0\0\0\0",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 100, b"\0" * 257 + b"ustar\x0000" + b"\0" * 100,
        b"\0" * 257 + b"ustar", b"L\x00\x00\x00\x01\x14\x02\x00" + b"\0" * 60, b"%PDF-1.7\n",
        b"MEI\x0c\x0b\x0a\x0b\x0e", b"[InternetShortcut]\r\nURL=http://x\r\n", b"@echo off\r\nstart x.exe\r\n",
        b"\xef\xbb\xbf  @ECHO OFF\r\n", b"rem x\r\n\n@echo off\n", b"#!/bin/sh\necho", b"Windows Registry Editor Version 5.00\r\n",
        b"REGEDIT4\r\n", b"\xff\xfeH\x00i\x00", b"\xfe\xff\x00H", b"plain text config=1\n" * 30, b"\x00\x01\x02\x03",
        b"", b"\xef\xbb\xbf", b"   \t\n", bytes(range(32, 127)) * 4, b"a" * 1000 + b"\x01" * 40, b"a" * 1000 + b"\x01" * 60,
        "texto acentuação çãõ\n".encode() * 20,
    ]
    rng = random.Random(1234)
    for _ in range(300):
        base = bytearray(rng.choice(headers) or b"x")
        for _ in range(rng.randint(1, 6)):
            if base:
                base[rng.randrange(len(base))] = rng.randrange(256)
        headers.append(bytes(base))
    for _ in range(100):
        headers.append(rng.randbytes(rng.randint(0, 600)))
    return headers


CORPUS = _corpus()


def _py_identify(header, ext, probe=b""):
    info = py_ft.identify(header, ext, probe)
    return {"kind": info.kind, "description": info.description, "group": info.group, "disguised": info.disguised}


@pytest.mark.parametrize("ext", EXTENSIONS)
def test_identify_equivalence(native, ext):
    for header in CORPUS:
        assert native.identify(header, ext) == _py_identify(header, ext), (header[:32], ext)


def test_iso_probe_equivalence(native):
    for probe in (b"CD001", b"CD001\x01", b"CD00", b"", b"BEA01"):
        for ext in (".iso", ".bin", ""):
            assert native.identify(b"\0" * 64, ext, probe) == _py_identify(b"\0" * 64, ext, probe)


def test_group_and_priority_equivalence(native):
    filters = [
        {},
        {"libraries": False, "drivers": False},
        {"executables": False, "scripts": False, "java": False},
        {"archives": False, "installers": False, "shortcuts": False, "data_sniffing": False},
    ]
    names = ["Game.exe", "crack.dll", "Setup_x64.exe", "steam_api64.dll", "readme.txt", "patch.bat", "data.pak"]
    for header in CORPUS[:120]:
        for ext in (".exe", ".pak", ".zip", ".bat", ".jar", ".msi", ".lnk", ""):
            py_info = py_ft.identify(header, ext)
            info = _py_identify(header, ext)
            for f in filters:
                merged = {**{k: True for k in ("executables", "libraries", "drivers", "scripts", "archives",
                                               "installers", "java", "shortcuts", "data_sniffing")}, **f}
                assert native.group_enabled(info, merged) == py_ft.group_enabled(py_info, ext, merged)
            for name in names:
                assert native.priority(info, name) == py_ft.priority(py_info, ext, name)


def test_identify_file_reads_header_and_iso_probe(native, tmp_path):
    iso = tmp_path / "disk.iso"
    iso.write_bytes(b"\0" * 0x8001 + b"CD001" + b"\0" * 100)
    assert native.identify_file(iso)["kind"] == "iso"
    disguised = tmp_path / "textures.pak"
    disguised.write_bytes(_pe())
    result = native.identify_file(disguised)
    assert result["group"] == "executable" and result["disguised"] is True
    assert native.extension_of(tmp_path / "A.TXT") == ".txt"
