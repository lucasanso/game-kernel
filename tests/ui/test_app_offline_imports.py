"""The desktop application is offline by construction, like the core binaries.

Extends Agent A's audit (tests/native/test_offline_imports.py, same forbidden lists) to GameKernel(.exe).
On Windows the check follows what the program really loads: the import closure of GameKernel.exe and of the
Qt plugins it uses (platforms, styles, image formats, icon engines), resolved inside the build folder. That
folder is shared with the test executable (QtTest), whose own deployment must not be blamed on the product;
the shipped folder itself is assembled clean by tools/make_distribution.py, which refuses any networking DLL,
and audited again after installation (tests/integration/test_distribution.py). Windows uses pefile (the
product CI does not build gk_native); Linux checks the executable's direct dynamic imports with nm/objdump.
"""

from __future__ import annotations

import sys
from pathlib import Path

from tests.integration.native_build import ROOT, build_project
from tests.native.test_offline_imports import FORBIDDEN_DLLS, WS2_ALLOWED, _elf_violations


# Qt Core's Windows event dispatcher initialises Winsock and uses WSAAsyncSelect for QSocketNotifier; it cannot
# resolve names or open connections by itself (that is QtNetwork, which is never shipped). Narrow, per-DLL
# exception: connect/getaddrinfo/send/recv... stay forbidden everywhere, Qt included.
PER_DLL_WS2_ALLOWED = {"qt6core.dll": {"WSAStartup", "WSACleanup", "WSAAsyncSelect"}}


def _pe_violations(path) -> list[str]:
    import pefile

    allowed = WS2_ALLOWED | PER_DLL_WS2_ALLOWED.get(Path(path).name.lower(), set())

    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        problems = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode("ascii", "replace").lower()
            for imp in entry.imports:
                name = imp.name.decode("ascii", "replace") if imp.name else f"#{imp.ordinal}"
                if dll in FORBIDDEN_DLLS or (dll == "ws2_32.dll" and name not in allowed):
                    problems.append(f"{path.name}: {dll}!{name}")
        return problems
    finally:
        pe.close()


def _pe_imports(path) -> set[str]:
    import pefile

    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        return {e.dll.decode("ascii", "replace").lower() for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])}
    finally:
        pe.close()


PRODUCT_PLUGIN_DIRS = ("platforms", "styles", "imageformats", "iconengines")


def _load_closure(exe) -> dict[str, str]:
    """DLLs (lower-case name -> who imports it) reachable from the program and its Qt plugins, among the files
    present in its folder; system DLLs outside the folder are covered by the per-binary import audit."""
    folder = exe.parent
    local = {p.name.lower(): p for p in folder.glob("*.dll")}
    roots = [exe] + [p for d in PRODUCT_PLUGIN_DIRS for p in sorted((folder / d).glob("*.dll"))]
    reached: dict[str, str] = {}
    queue = list(roots)
    while queue:
        binary = queue.pop()
        for dll in _pe_imports(binary):
            if dll not in reached:
                reached[dll] = binary.name
                if dll in local:
                    queue.append(local[dll])
    return reached


def test_desktop_application_imports_no_network_code():
    exe = build_project("native-app", ROOT / "cpp" / "app", "GameKernel")
    if sys.platform == "win32":
        closure = _load_closure(exe)
        assert "qt6widgets.dll" in closure and "qt6svg.dll" in closure, sorted(closure)
        problems = [f"{dll} (importada por {who})" for dll, who in sorted(closure.items()) if dll in FORBIDDEN_DLLS]
        local = {p.name.lower(): p for p in exe.parent.glob("*.dll")}
        for dll in [exe.name.lower(), *closure]:
            binary = exe if dll == exe.name.lower() else local.get(dll)
            if binary is not None:
                problems += _pe_violations(binary)
    else:
        problems = _elf_violations(exe)
    assert problems == [], f"importações de rede no aplicativo: {problems}"


def _pe_with_imports(imports: dict[str, list[str]]) -> bytes:
    """Minimal PE32+ whose import directory lists ``imports`` ({dll: [function, ...]})."""
    import struct
    pe = bytearray(0x1200)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
    oh = 0x98
    struct.pack_into("<H", pe, oh, 0x20B)
    struct.pack_into("<II", pe, oh + 32, 0x1000, 0x200)              # section / file alignment
    struct.pack_into("<II", pe, oh + 56, 0x2000, 0x200)              # size of image / headers
    struct.pack_into("<I", pe, oh + 108, 16)                         # number of data directories
    struct.pack_into("<II", pe, oh + 112 + 8, 0x1000, 20 * (len(imports) + 1))   # import directory
    sh = oh + 0xF0
    pe[sh:sh + 8] = b".idata\0\0"
    struct.pack_into("<IIII", pe, sh + 8, 0x1000, 0x1000, 0x1000, 0x200)
    struct.pack_into("<I", pe, sh + 36, 0xC0000040)

    def put(rva: int, data: bytes) -> None:
        pe[0x200 + rva - 0x1000: 0x200 + rva - 0x1000 + len(data)] = data

    strings = 0x1800
    for i, (dll, functions) in enumerate(imports.items()):
        thunks = 0x1200 + i * 0x80
        name_rva = strings
        put(name_rva, dll.encode() + b"\0")
        strings += len(dll) + 2
        entries = []
        for fn in functions:
            put(strings, b"\0\0" + fn.encode() + b"\0")
            entries.append(strings)
            strings += len(fn) + 4
        put(thunks, struct.pack(f"<{len(entries) + 1}Q", *entries, 0))
        put(0x1000 + 20 * i, struct.pack("<IIIII", thunks, 0, 0, name_rva, thunks))
    return bytes(pe)


def test_pe_audit_flags_networking_imports_but_not_byte_order_helpers(tmp_path):
    sample = tmp_path / "net.exe"
    sample.write_bytes(_pe_with_imports({"ws2_32.dll": ["connect", "htonl"], "wininet.dll": ["InternetOpenA"]}))
    # htonl (byte order, used by libyara) is tolerated; connect and WinINet are not.
    assert sorted(_pe_violations(sample)) == ["net.exe: wininet.dll!InternetOpenA", "net.exe: ws2_32.dll!connect"]


def test_load_closure_follows_only_what_the_program_loads(tmp_path):
    def write(rel: str, imports: dict[str, list[str]]) -> Path:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_pe_with_imports(imports))
        return path

    exe = write("GameKernel.exe", {"qt6widgets.dll": ["a"], "qt6svg.dll": ["b"], "kernel32.dll": ["c"]})
    write("qt6widgets.dll", {"qt6gui.dll": ["d"]})
    write("qt6gui.dll", {"qt6core.dll": ["e"]})
    write("qt6svg.dll", {"qt6core.dll": ["e"]})
    write("qt6core.dll", {"kernel32.dll": ["f"]})
    write("qt6test.dll", {"qt6network.dll": ["g"]})           # deployed for the test executable only
    write("qt6network.dll", {"ws2_32.dll": ["connect"]})
    write("platforms/qwindows.dll", {"qt6gui.dll": ["h"]})
    closure = _load_closure(exe)
    assert {"qt6widgets.dll", "qt6svg.dll", "qt6gui.dll", "qt6core.dll", "kernel32.dll"} <= set(closure)
    assert "qt6network.dll" not in closure and "qt6test.dll" not in closure
    write("styles/qmodernwindowsstyle.dll", {"qt6network.dll": ["g"]})   # a plugin the program loads
    assert _load_closure(exe)["qt6network.dll"] == "qmodernwindowsstyle.dll"


def test_qt_core_event_dispatcher_exception_is_narrow(tmp_path):
    winsock_init = {"ws2_32.dll": ["WSAStartup", "WSACleanup", "WSAAsyncSelect"]}
    (tmp_path / "Qt6Core.dll").write_bytes(_pe_with_imports(winsock_init))
    assert _pe_violations(tmp_path / "Qt6Core.dll") == []
    (tmp_path / "Qt6Core.dll").write_bytes(_pe_with_imports({"ws2_32.dll": ["WSAStartup", "connect"]}))
    assert _pe_violations(tmp_path / "Qt6Core.dll") == ["Qt6Core.dll: ws2_32.dll!connect"]
    (tmp_path / "GameKernel.exe").write_bytes(_pe_with_imports(winsock_init))       # not allowed for our code
    assert len(_pe_violations(tmp_path / "GameKernel.exe")) == 3
