"""Build the benign PE corpus with mingw-w64 (used by tests/native/test_pe.py).

Nothing here is ever executed: the binaries are only parsed. Output goes to the directory given
on the command line (a pytest temporary directory)."""

from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLCHAINS = {"x64": "x86_64-w64-mingw32", "x86": "i686-w64-mingw32"}


def available() -> bool:
    return all(shutil.which(f"{p}-gcc") and shutil.which(f"{p}-windres") for p in TOOLCHAINS.values())


def _run(args: list[str], cwd: Path) -> None:
    subprocess.run(args, cwd=cwd, check=True, capture_output=True, timeout=180)


def build(out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    work = out / "work"
    work.mkdir(exist_ok=True)
    for name in ("basic.c", "exports.c", "exports.def", "resources.rc", "resources.c", "manifest.xml"):
        shutil.copy(HERE / name, work / name)
    (work / "noise.bin").write_bytes(random.Random(7).randbytes(8192))
    produced: list[Path] = []
    for arch, prefix in TOOLCHAINS.items():
        gcc, windres = f"{prefix}-gcc", f"{prefix}-windres"
        basic = out / f"basic_{arch}.exe"
        _run([gcc, "-O1", "basic.c", "-o", str(basic), f"-Wl,--pdb={out / f'basic_{arch}.pdb'}", "-luser32"], work)
        produced.append(basic)
        stripped = out / f"basic_{arch}_stripped.exe"
        _run([gcc, "-O2", "-s", "basic.c", "-o", str(stripped), "-luser32"], work)
        produced.append(stripped)
        dll = out / f"exports_{arch}.dll"
        _run([gcc, "-shared", "-O1", "exports.c", "exports.def", "-o", str(dll)], work)
        produced.append(dll)
        shutil.copy(basic, work / "embedded.bin")
        _run([windres, "resources.rc", "-O", "coff", "-o", f"resources_{arch}.res"], work)
        res_exe = out / f"resources_{arch}.exe"
        _run([gcc, "-O1", "-mwindows", "resources.c", f"resources_{arch}.res", "-o", str(res_exe)], work)
        produced.append(res_exe)
        overlay = out / f"overlay_{arch}.exe"
        overlay.write_bytes(stripped.read_bytes() + b"PK\x03\x04" + random.Random(3).randbytes(4096))
        produced.append(overlay)
    shutil.rmtree(work, ignore_errors=True)
    return produced


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else os.getcwd())
    for p in build(target):
        print(p)
