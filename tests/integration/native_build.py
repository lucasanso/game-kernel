"""Build-and-run helpers so pytest controls the C++ test executables (Test Engine in Python).

Native projects are configured once per session into ``build/<name>`` (git-ignored). When the
toolchain (CMake + compiler + Qt 6) is missing, tests are skipped with the reason — unless
``GK_NATIVE_REQUIRED=1`` (set in CI), in which case a missing toolchain is a failure, so an
integration problem can never be hidden by a skip.
"""

from __future__ import annotations

import os
import shlex
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
    # Extra configure arguments, e.g. the vcpkg toolchain and the Qt prefix on Windows CI.
    extra_args += shlex.split(os.environ.get("GK_CMAKE_ARGS", ""), posix=sys.platform != "win32")
    build_dir = BUILD_ROOT / name
    # Ninja needs a compiler environment; on Windows the default Visual Studio generator finds MSVC itself.
    generator = ["-G", "Ninja"] if shutil.which("ninja") and sys.platform != "win32" else []
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
            _deploy_qt_runtime(candidate)
            return candidate
    pytest.fail(f"executável {exe} não encontrado em {build_dir}")


def _deploy_qt_runtime(executable: Path) -> None:
    """Windows: copy the exact Qt DLLs next to the executable (windeployqt). The application folder is
    searched before PATH, so a different Qt found on PATH (other tools, PySide6) can never be loaded."""
    if sys.platform != "win32":
        return
    tool = shutil.which("windeployqt") or shutil.which("windeployqt6")
    if not tool:
        _unavailable("windeployqt não encontrado (pasta bin do Qt fora do PATH)")
    proc = subprocess.run([tool, "--no-translations", "--no-compiler-runtime", "--no-opengl-sw",
                           "--no-system-d3d-compiler", str(executable)], capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.fail(f"windeployqt falhou para {executable.name}:\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}")


# Windows NTSTATUS values seen as process exit codes when a program cannot even start.
NTSTATUS = {
    0xC0000135: "STATUS_DLL_NOT_FOUND (DLL ausente)",
    0xC0000139: "STATUS_ENTRYPOINT_NOT_FOUND (DLL de versão incompatível)",
    0xC000007B: "STATUS_INVALID_IMAGE_FORMAT (DLL de 32/64 bits trocada)",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN",
}


def describe_exit(code: int) -> str:
    unsigned = code & 0xFFFFFFFF
    return f"{code} ({NTSTATUS[unsigned]})" if unsigned in NTSTATUS else str(code)


def run_qtest(executable: Path, env_extra: dict[str, str], timeout: int = 600) -> tuple[int, str]:
    env = dict(os.environ)
    env.update(env_extra)
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    report = executable.parent / f"{executable.stem}-report.txt"
    proc = subprocess.run([str(executable), "-o", f"{report},txt"], env=env, capture_output=True, text=True,
                          timeout=timeout)
    text = report.read_text(encoding="utf-8", errors="replace") if report.exists() else ""
    return proc.returncode, (f"código de saída: {describe_exit(proc.returncode)}\n" + text + "\n"
                             + proc.stdout[-2000:] + "\n" + proc.stderr[-4000:])
