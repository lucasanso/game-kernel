"""The desktop application is offline by construction, like the core binaries.

Extends Agent A's audit (tests/native/test_offline_imports.py, same forbidden lists) to GameKernel(.exe):
its own imports, and on Windows also every DLL that windeployqt placed next to it — that folder is what the
installer ships, so e.g. Qt6Network.dll must never appear there. Windows uses pefile (the product CI does
not build gk_native); Linux checks the executable's direct dynamic imports with nm/objdump.
"""

from __future__ import annotations

import sys

from tests.integration.native_build import ROOT, build_project
from tests.native.test_offline_imports import FORBIDDEN_DLLS, WS2_ALLOWED, _elf_violations


def _pe_violations(path) -> list[str]:
    import pefile

    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        problems = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode("ascii", "replace").lower()
            for imp in entry.imports:
                name = imp.name.decode("ascii", "replace") if imp.name else f"#{imp.ordinal}"
                if dll in FORBIDDEN_DLLS or (dll == "ws2_32.dll" and name not in WS2_ALLOWED):
                    problems.append(f"{path.name}: {dll}!{name}")
        return problems
    finally:
        pe.close()


def test_desktop_application_imports_no_network_code():
    exe = build_project("native-app", ROOT / "cpp" / "app", "GameKernel")
    if sys.platform == "win32":
        problems = _pe_violations(exe)
        deployed = sorted(p.name.lower() for p in exe.parent.rglob("*.dll"))
        assert deployed, "windeployqt não colocou as DLLs do Qt ao lado do executável"
        problems += [f"DLL de rede implantada: {name}" for name in deployed if name in FORBIDDEN_DLLS]
        for dll in exe.parent.glob("*.dll"):
            problems += _pe_violations(dll) if dll.name.lower().startswith(("gk", "libyara", "libsodium")) else []
    else:
        problems = _elf_violations(exe)
    assert problems == [], f"importações de rede no aplicativo: {problems}"


def _networking_pe() -> bytes:
    """Minimal PE32+ importing ws2_32!connect, ws2_32!htonl and wininet!InternetOpenA."""
    import struct
    pe = bytearray(0x600)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
    oh = 0x98
    struct.pack_into("<H", pe, oh, 0x20B)
    struct.pack_into("<II", pe, oh + 32, 0x1000, 0x200)              # section / file alignment
    struct.pack_into("<II", pe, oh + 56, 0x2000, 0x200)              # size of image / headers
    struct.pack_into("<I", pe, oh + 108, 16)                         # number of data directories
    struct.pack_into("<II", pe, oh + 112 + 8, 0x1000, 60)            # import directory
    sh = oh + 0xF0
    pe[sh:sh + 8] = b".idata\0\0"
    struct.pack_into("<IIII", pe, sh + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", pe, sh + 36, 0xC0000040)

    def put(rva: int, data: bytes) -> None:
        pe[0x200 + rva - 0x1000: 0x200 + rva - 0x1000 + len(data)] = data

    put(0x1200, b"ws2_32.dll\0")
    put(0x1210, b"wininet.dll\0")
    put(0x1220, b"\0\0connect\0")
    put(0x1230, b"\0\0InternetOpenA\0")
    put(0x1240, b"\0\0htonl\0")
    put(0x1100, struct.pack("<QQQ", 0x1220, 0x1240, 0))
    put(0x1120, struct.pack("<QQ", 0x1230, 0))
    put(0x1000, struct.pack("<IIIII", 0x1100, 0, 0, 0x1200, 0x1100))
    put(0x1014, struct.pack("<IIIII", 0x1120, 0, 0, 0x1210, 0x1120))
    return bytes(pe)


def test_pe_audit_flags_networking_imports_but_not_byte_order_helpers(tmp_path):
    sample = tmp_path / "net.exe"
    sample.write_bytes(_networking_pe())
    # htonl (byte order, used by libyara) is tolerated; connect and WinINet are not.
    assert sorted(_pe_violations(sample)) == ["net.exe: wininet.dll!InternetOpenA", "net.exe: ws2_32.dll!connect"]
