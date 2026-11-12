"""Application icon and Windows executable resources (cpp/app).

* assets/gamekernel.ico is a valid multi-size icon and still matches assets/gamekernel.svg
  (regenerate with ``python tools/make_app_icon.py`` when the logo changes);
* on Windows, GameKernel.exe carries the icon and a VERSIONINFO whose version is the one in
  cpp/app/CMakeLists.txt (read back from the built PE with pefile).
"""

from __future__ import annotations

import io
import re
import struct
import sys

import pytest
from PIL import Image, ImageChops, ImageStat

from tests.integration.native_build import ROOT, build_project
from tools import make_app_icon

ICO = ROOT / "assets" / "gamekernel.ico"
SVG = ROOT / "assets" / "gamekernel.svg"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _ico_entries(data: bytes) -> dict[int, bytes]:
    reserved, kind, count = struct.unpack_from("<HHH", data, 0)
    assert (reserved, kind) == (0, 1), "não é um arquivo .ico"
    entries = {}
    for i in range(count):
        w, h, colors, _res, planes, bpp, size, offset = struct.unpack_from("<BBBBHHII", data, 6 + 16 * i)
        assert w == h and colors == 0 and planes == 1 and bpp == 32
        assert offset + size <= len(data)
        entries[w or 256] = data[offset:offset + size]
    return entries


def _cmake_version() -> str:
    text = (ROOT / "cpp" / "app" / "CMakeLists.txt").read_text(encoding="utf-8")
    match = re.search(r"project\(gk_app VERSION (\d+\.\d+\.\d+)", text)
    assert match, "versão não encontrada em cpp/app/CMakeLists.txt"
    return match.group(1)


def test_icon_has_every_size_as_transparent_png():
    entries = _ico_entries(ICO.read_bytes())
    assert sorted(entries) == list(make_app_icon.SIZES)
    for size, payload in entries.items():
        assert payload.startswith(PNG_SIGNATURE)
        image = Image.open(io.BytesIO(payload))
        assert image.size == (size, size) and image.mode == "RGBA"
        assert image.getpixel((0, 0))[3] == 0                      # transparent corner
        assert image.getpixel((size // 2, size // 10))[3] > 200    # opaque shield rim


def test_icon_matches_the_svg_logo():
    entries = _ico_entries(ICO.read_bytes())
    svg = SVG.read_bytes()
    for size in make_app_icon.SIZES:
        committed = Image.open(io.BytesIO(entries[size])).convert("RGBA")
        fresh = Image.open(io.BytesIO(make_app_icon.render_png(svg, size))).convert("RGBA")
        diff = ImageStat.Stat(ImageChops.difference(committed, fresh)).mean
        assert max(diff) <= 2.0, (f"{size}px difere do SVG ({diff}); rode: python tools/make_app_icon.py")


def test_build_ico_layout_round_trips():
    pngs = {16: PNG_SIGNATURE + b"a", 256: PNG_SIGNATURE + b"bb"}
    entries = _ico_entries(make_app_icon.build_ico(pngs))
    assert entries == pngs


@pytest.mark.skipif(sys.platform != "win32", reason="recursos PE (ícone e VERSIONINFO) só existem no executável Windows")
def test_windows_executable_has_icon_and_version():
    import pefile

    exe = build_project("native-app", ROOT / "cpp" / "app", "GameKernel")
    pe = pefile.PE(str(exe))
    try:
        strings = {}
        for info in getattr(pe, "FileInfo", []) or []:
            for entry in info:
                for table in getattr(entry, "StringTable", []):
                    strings.update({k.decode("utf-8"): v.decode("utf-8") for k, v in table.entries.items()})
        version = _cmake_version()
        assert strings.get("ProductName") == "Game Kernel"
        assert strings.get("FileVersion") == version and strings.get("ProductVersion") == version
        assert strings.get("OriginalFilename") == "GameKernel.exe"
        assert "antivírus offline" in strings.get("FileDescription", "")
        fixed = pe.VS_FIXEDFILEINFO[0]
        major, minor, patch = (int(x) for x in version.split("."))
        assert (fixed.FileVersionMS, fixed.FileVersionLS) == ((major << 16) | minor, patch << 16)

        groups = [e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries
                  if e.id == pefile.RESOURCE_TYPE["RT_GROUP_ICON"]]
        icons = [e for e in pe.DIRECTORY_ENTRY_RESOURCE.entries if e.id == pefile.RESOURCE_TYPE["RT_ICON"]]
        assert groups and icons, "GameKernel.exe sem ícone"
        assert len(icons[0].directory.entries) == len(make_app_icon.SIZES)
    finally:
        pe.close()
