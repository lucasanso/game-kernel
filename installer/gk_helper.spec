# PyInstaller spec of the Game Kernel helper process (gk-helper.exe).
#
#   pyinstaller installer/gk_helper.spec --distpath dist --workpath build/pyinstaller
#
# One-folder build (faster start, fewer antivirus false positives than one-file self-extractors).
# Console subsystem on purpose: the application talks to the helper over stdin/stdout pipes and
# starts it with CREATE_NO_WINDOW, so no window ever appears. The user never runs it directly.
# The result goes to <install>/helper/ (see installer/gamekernel.iss and docs/BUILD.md).
import os
from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent

hidden = [
    "gamekernel.ipc.services.reports",
    "gamekernel.core.report_html",
    "gamekernel.core.report_pdf",
    "reportlab.graphics.barcode.common",   # loaded dynamically by reportlab
]

# Heavy packages the helper never imports (they belong to other tools or to development).
excluded = [
    "tkinter", "PySide6", "shiboken6", "yara", "pefile", "watchdog", "py7zr", "rarfile", "pycdlib", "signify",
    "pytest", "pytestqt", "PyInstaller", "IPython", "matplotlib", "numpy",
]

a = Analysis(
    [str(ROOT / "gk_helper.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=hidden,
    excludes=excluded,
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="gk-helper",
    console=True,
    disable_windowed_traceback=True,
    upx=False,
    icon=None,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="gk-helper")
