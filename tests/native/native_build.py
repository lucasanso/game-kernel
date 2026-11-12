"""Build-and-run helpers so pytest controls the C++ test executables (Test Engine in Python).

Native projects are configured once per session into ``build/<name>`` (git-ignored). When the
toolchain (CMake + compiler + Qt 6) is missing, tests are skipped with the reason — unless
``GK_NATIVE_REQUIRED=1`` (set in CI), in which case a missing toolchain is a failure, so an
integration problem can never be hidden by a skip.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BUILD_ROOT = ROOT / "build"


def _unavailable(reason: str):
    if os.environ.get("GK_NATIVE_REQUIRED") == "1":
        pytest.fail(f"toolchain nativo obrigatório indisponível: {reason}")
    pytest.skip(reason)


SANITIZER_FLAGS = "-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined"


def build_project(name: str, source: Path, target: str, extra_args: list[str] | None = None) -> Path:
    """Configure/build ``target``. ``GK_NATIVE_SANITIZE=1`` builds a separate ASan+UBSan variant
    (GCC/Clang), so the whole Python-driven suite exercises instrumented C++ code."""
    cmake = shutil.which("cmake")
    if not cmake:
        _unavailable("cmake não encontrado")
    extra_args = list(extra_args or [])
    config = os.environ.get("GK_NATIVE_CONFIG", "Release")
    if os.environ.get("GK_NATIVE_SANITIZE") == "1" and sys.platform != "win32":
        name += "-asan"
        config = "Debug"
        extra_args.append(f"-DCMAKE_CXX_FLAGS={SANITIZER_FLAGS}")
        # Distinct exit codes: a sanitizer report must never look like a legitimate rejection (exit 1).
        os.environ.setdefault("ASAN_OPTIONS", "exitcode=99:detect_leaks=1")
        os.environ.setdefault("UBSAN_OPTIONS", "halt_on_error=1:exitcode=98:print_stacktrace=1")
    build_dir = BUILD_ROOT / name
    generator = ["-G", "Ninja"] if shutil.which("ninja") else []
    if not (build_dir / "CMakeCache.txt").exists():
        proc = subprocess.run(
            [cmake, "-S", str(source), "-B", str(build_dir), f"-DCMAKE_BUILD_TYPE={config}", *generator,
             *extra_args],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            shutil.rmtree(build_dir, ignore_errors=True)
            _unavailable(f"configuração CMake falhou:\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}")
    proc = subprocess.run([cmake, "--build", str(build_dir), "--config", config, "--target", target],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.fail(f"compilação de {target} falhou:\n{proc.stdout[-6000:]}\n{proc.stderr[-3000:]}")
    exe = target + (".exe" if sys.platform == "win32" else "")
    for candidate in (build_dir / exe, build_dir / config / exe):
        if candidate.exists():
            return candidate
    pytest.fail(f"executável {exe} não encontrado em {build_dir}")


def run_qtest(executable: Path, env_extra: dict[str, str], timeout: int = 600) -> tuple[int, str]:
    env = dict(os.environ)
    env.update(env_extra)
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    report = executable.parent / f"{executable.stem}-report.txt"
    proc = subprocess.run([str(executable), "-o", f"{report},txt"], env=env, capture_output=True, text=True,
                          timeout=timeout)
    text = report.read_text(encoding="utf-8", errors="replace") if report.exists() else ""
    return proc.returncode, text + "\n" + proc.stderr[-4000:]
