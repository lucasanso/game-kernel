import struct

from gamekernel.core.filetypes import identify


def _pe(dll=False, subsystem=3, dotnet=False):
    data = bytearray(1024)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x80 + 4, 0x8664)
    struct.pack_into("<H", data, 0x80 + 22, 0x2022 if dll else 0x0022)
    opt = 0x80 + 24
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<H", data, opt + 68, subsystem)
    if dotnet:
        struct.pack_into("<I", data, opt + 112 + 14 * 8, 0x2000)
    return bytes(data)


def test_pe_kinds():
    assert identify(_pe(), ".exe").kind == "pe_exe"
    assert identify(_pe(dll=True), ".dll").kind == "pe_dll"
    assert identify(_pe(subsystem=1), ".sys").kind == "pe_sys"
    assert identify(_pe(dotnet=True), ".exe").kind == "pe_dotnet_exe"


def test_disguised_pe_detected():
    info = identify(_pe(), ".pak")
    assert info.group == "executable" and info.disguised


def test_archives_and_scripts():
    assert identify(b"PK\x03\x04" + b"\0" * 40, ".zip").kind == "zip"
    assert identify(b"Rar!\x1a\x07\x01\x00", ".rar").kind == "rar"
    assert identify(b"7z\xbc\xaf\x27\x1c" + b"\0" * 10, ".7z").kind == "7z"
    assert identify(b"@echo off\r\nstart x", ".txt").kind == "bat"
    assert identify(b"Write-Host 1", ".ps1").kind == "ps1"
    assert identify(b"L\x00\x00\x00\x01\x14\x02\x00" + b"\0" * 60, ".lnk").kind == "lnk"
    assert identify(b"\0" * 64, ".iso", iso_probe=b"CD001\x01").kind == "iso"
    assert identify(b"garbage", ".zip").kind == "corrupt_archive"
