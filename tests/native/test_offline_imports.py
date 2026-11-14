"""Offline by construction: no Game Kernel binary imports networking code.

docs/SECURITY.md promises that no network library is linked into the C++ binaries. On Windows (the product,
with statically linked dependencies) every import of every binary is checked with the core's own PE parser;
WS2_32 is tolerated only for the byte-order helpers libyara uses. On Linux the binaries' direct dynamic
imports are checked with `nm`/`objdump` (shared system libraries are outside this audit).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
IS_WINDOWS = os.name == "nt"

# Windows: DLLs whose only purpose is network I/O (or a networking framework).
FORBIDDEN_DLLS = {"wininet.dll", "winhttp.dll", "urlmon.dll", "mswsock.dll", "wsock32.dll", "dnsapi.dll",
                  "httpapi.dll", "websocket.dll", "webio.dll", "qt6network.dll", "qt6websockets.dll",
                  "libcurl.dll", "libcurl-x64.dll"}
WS2_ALLOWED = {"htonl", "htons", "ntohl", "ntohs"}            # pure byte-order helpers (libyara)

# Linux: libc networking entry points and networking libraries.
FORBIDDEN_SYMBOLS = {"socket", "connect", "bind", "listen", "accept", "accept4", "getaddrinfo", "getnameinfo",
                     "gethostbyname", "gethostbyname_r", "gethostbyaddr", "sendto", "recvfrom", "sendmsg",
                     "recvmsg", "send", "recv"}
FORBIDDEN_LIBS = ("libcurl", "libssl", "libQt6Network", "libresolv", "libnsl")


def _binaries(native) -> list[Path]:
    found = [Path(native.__file__)]
    exe = ".exe" if IS_WINDOWS else ""
    for preset in ("linux-release", "windows-release"):
        base = ROOT / "build" / preset / "cpp"
        for rel in (f"worker/gk-scanworker{exe}", f"worker/Release/gk-scanworker{exe}",
                    f"cli/gk-cli{exe}", f"cli/Release/gk-cli{exe}"):
            if (base / rel).exists():
                found.append(base / rel)
    for rel in (f"native-updates/gk-update{exe}", f"native-updates/Release/gk-update{exe}"):
        if (ROOT / "build" / rel).exists():
            found.append(ROOT / "build" / rel)
    return found


def _pe_violations(native, path: Path) -> list[str]:
    info = native.parse_pe_file(str(path))
    assert info["valid"], path
    problems = []
    for imp in info["imports"]:
        dll = imp["dll"].lower()
        name = imp["name"] or imp["name_from_ordinal"] or f"#{imp['ordinal']}"
        if dll in FORBIDDEN_DLLS:
            problems.append(f"{dll}!{name}")
        elif dll == "ws2_32.dll" and name not in WS2_ALLOWED:
            problems.append(f"{dll}!{name}")
    return problems


def _elf_violations(path: Path) -> list[str]:
    nm = shutil.which("nm")
    objdump = shutil.which("objdump")
    if nm is None or objdump is None:
        pytest.skip("binutils (nm/objdump) indisponível")
    undefined = subprocess.run([nm, "-D", "--undefined-only", str(path)], capture_output=True, text=True,
                               check=True).stdout.split()
    symbols = {s.split("@")[0] for s in undefined}
    needed = [line.split()[-1] for line in subprocess.run([objdump, "-p", str(path)], capture_output=True,
                                                          text=True, check=True).stdout.splitlines()
              if line.strip().startswith("NEEDED")]
    return sorted(symbols & FORBIDDEN_SYMBOLS) + [lib for lib in needed if lib.startswith(FORBIDDEN_LIBS)]


def test_no_binary_imports_network_code(native):
    binaries = _binaries(native)
    report = {}
    for path in binaries:
        problems = _pe_violations(native, path) if IS_WINDOWS else _elf_violations(path)
        if problems:
            report[str(path)] = problems
    assert report == {}, f"importações de rede encontradas: {report}"
    # The audit must cover more than the Python module when the executables were built.
    if os.environ.get("GK_REQUIRE_CLI") == "1":
        assert any("gk-cli" in p.name for p in binaries) and any("gk-scanworker" in p.name for p in binaries)


def test_audit_detects_a_networking_import(native, tmp_path):
    """The checker itself works: a PE importing ws2_32!connect and wininet is flagged."""
    import struct
    pe = bytearray(0x600)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
    oh = 0x98
    struct.pack_into("<H", pe, oh, 0x20B)
    struct.pack_into("<II", pe, oh + 32, 0x1000, 0x200)
    struct.pack_into("<II", pe, oh + 56, 0x2000, 0x200)
    struct.pack_into("<I", pe, oh + 108, 16)
    struct.pack_into("<II", pe, oh + 112 + 8, 0x1000, 40)            # import directory
    sh = oh + 0xF0
    pe[sh:sh + 8] = b".idata\0\0"
    struct.pack_into("<IIII", pe, sh + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", pe, sh + 36, 0xC0000040)
    base, rva = 0x200, 0x1000
    # descriptors at 0x1000 (2 + terminator), INTs at 0x1100/0x1120, names/hints from 0x1200
    def put(off, data):
        pe[base + off - rva: base + off - rva + len(data)] = data
    put(0x1200, b"ws2_32.dll\0")
    put(0x1210, b"wininet.dll\0")
    put(0x1220, b"\0\0connect\0")
    put(0x1230, b"\0\0InternetOpenA\0")
    put(0x1100, struct.pack("<QQ", 0x1220, 0))
    put(0x1120, struct.pack("<QQ", 0x1230, 0))
    put(0x1000, struct.pack("<IIIII", 0x1100, 0, 0, 0x1200, 0x1100))
    put(0x1014, struct.pack("<IIIII", 0x1120, 0, 0, 0x1210, 0x1120))
    f = tmp_path / "net.exe"
    f.write_bytes(bytes(pe))
    assert set(_pe_violations(native, f)) == {"ws2_32.dll!connect", "wininet.dll!InternetOpenA"}
