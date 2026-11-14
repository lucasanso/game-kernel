# PyInstaller spec of the Game Kernel helper process (gk-helper.exe).
#
#   pyinstaller installer/gk_helper.spec --distpath dist --workpath build/pyinstaller
#
# One-folder build (faster start, fewer antivirus false positives than one-file self-extractors).
# Console subsystem on purpose: the application talks to the helper over stdin/stdout pipes and
# starts it with CREATE_NO_WINDOW, so no window ever appears. The user never runs it directly.
# The result goes to <install>/helper/ (see installer/gamekernel.iss and docs/BUILD.md).
import os
import sys
from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent
sys.path.insert(0, str(ROOT))
from gamekernel.helper.services import SERVICE_MODULES  # noqa: E402  (single list of service modules)

# Service modules are imported by name at start-up, so PyInstaller cannot see them: list every one of them
# from the registry itself (a module left out here would silently drop its methods from the frozen helper).
hidden = [
    *SERVICE_MODULES,
    "gamekernel.reports.render_html",
    "gamekernel.reports.render_pdf",
    "reportlab.graphics.barcode.common",   # loaded dynamically by reportlab
]

# Heavy packages the helper never imports (they belong to other tools or to development).
excluded = [
    "tkinter", "PySide6", "shiboken6", "yara", "pefile", "watchdog", "py7zr", "rarfile", "pycdlib", "signify",
    "pytest", "pytestqt", "PyInstaller", "IPython", "matplotlib", "numpy",
]

a = Analysis(
    [str(ROOT / "gamekernel" / "helper" / "entry.py")],
    pathex=[str(ROOT)],
    binaries=[],
    # monitor.ps1 runs inside the Windows Sandbox VM; manager.py looks for it next to itself.
    datas=[(str(ROOT / "gamekernel" / "sandbox" / "monitor.ps1"), "gamekernel/sandbox")],
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
