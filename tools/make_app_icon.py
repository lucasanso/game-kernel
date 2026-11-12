#!/usr/bin/env python3
"""Render assets/gamekernel.svg into assets/gamekernel.ico (Windows executable and installer icon).

Run again whenever the logo changes; ``tests/ui/test_app_resources.py`` fails if the committed .ico no
longer matches the SVG. Each size is rendered from the vector source (no down-scaling of a large bitmap)
and stored as a PNG entry, which Windows Vista and later read natively.

Usage:  python tools/make_app_icon.py [--svg PATH] [--out PATH]
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def render_png(svg: bytes, size: int) -> bytes:
    """PNG bytes of ``svg`` rendered at ``size``×``size`` with a transparent background."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
    from PySide6.QtGui import QGuiApplication, QImage, QPainter
    from PySide6.QtSvg import QSvgRenderer

    _app = QGuiApplication.instance() or QGuiApplication([])  # QSvgRenderer needs a GUI application
    renderer = QSvgRenderer(QByteArray(svg))
    if not renderer.isValid():
        raise ValueError("SVG inválido")
    image = QImage(size, size, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter)
    painter.end()
    buffer = QBuffer()
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    if not image.save(buffer, "PNG"):
        raise RuntimeError(f"falha ao codificar PNG {size}px")
    return bytes(buffer.data())


def build_ico(pngs: dict[int, bytes]) -> bytes:
    """ICO container (ICONDIR + ICONDIRENTRY[] + PNG payloads), sizes in ascending order."""
    sizes = sorted(pngs)
    header = struct.pack("<HHH", 0, 1, len(sizes))
    offset = len(header) + 16 * len(sizes)
    entries, payload = b"", b""
    for size in sizes:
        data = pngs[size]
        dim = 0 if size >= 256 else size          # 0 means 256 in the ICO directory
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset + len(payload))
        payload += data
    return header + entries + payload


def make_icon(svg_path: Path, out_path: Path) -> list[int]:
    svg = svg_path.read_bytes()
    ico = build_ico({size: render_png(svg, size) for size in SIZES})
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    tmp.write_bytes(ico)
    os.replace(tmp, out_path)
    return list(SIZES)


def main(argv: list[str] | None = None) -> int:
    _utf8_stdio()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--svg", type=Path, default=ROOT / "assets" / "gamekernel.svg")
    parser.add_argument("--out", type=Path, default=ROOT / "assets" / "gamekernel.ico")
    args = parser.parse_args(argv)
    try:
        sizes = make_icon(args.svg, args.out)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 1
    print(f"{args.out}: {', '.join(f'{s}px' for s in sizes)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
