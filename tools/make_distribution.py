#!/usr/bin/env python3
"""Assemble the Game Kernel product folder, its integrity manifest and the portable ZIP.

The folder is what the Windows installer (installer/gamekernel.iss) copies to Program Files and what the
portable ZIP contains:

    GameKernel.exe, Qt runtime (windeployqt), gk-cli.exe, gk-scanworker.exe, gk-update.exe, MSVC runtime
    helper/                 frozen gk-helper (PyInstaller one-folder)
    signatures/             bundled YARA, indicators, IOC, ClamAV and component data (+ keys/release.pub)
    contracts/              threat_catalog.json (explanations and recommendations of the risk engine)
    docs/                   USAGE, PRIVACY, LIMITATIONS
    MANIFEST.sha256         SHA-256 of every other file (sha256sum format)

Safety checks (the build fails instead of shipping something wrong): required files present, no private key
material, no networking DLL, no conflicting DLLs with the same name, no portable.flag in the installed folder.
The portable ZIP is the same folder plus ``portable.flag`` (data then lives in ``<folder>/data``).

Usage (Windows CI, see .github/workflows/ci.yml):
    python tools/make_distribution.py --app <GameKernel.exe> --bin <gk-cli.exe> --bin <gk-scanworker.exe> \
        --bin <gk-update.exe> --helper dist/gk-helper --crt-dir <Microsoft.VC143.CRT> \
        --out dist/GameKernel --portable-zip dist/GameKernel-<versão>-portable.zip
    python tools/make_distribution.py --print-version
    python tools/make_distribution.py --verify <installed folder>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "MANIFEST.sha256"
SIGNATURE_DIRS = ("yara", "internal", "ioc", "clamav", "data")
# Data files the core loads at run time from its resource folder (cpp/scan Config): missing ones degrade
# the analysis, so they are copied and required explicitly.
RESOURCE_FILES = ("contracts/threat_catalog.json",)
DOCS = ("USAGE.md", "PRIVACY.md", "LIMITATIONS.md")
# DLLs whose only purpose is network I/O; the product is offline by construction (docs/SECURITY.md).
NETWORK_DLLS = {"wininet.dll", "winhttp.dll", "urlmon.dll", "mswsock.dll", "wsock32.dll", "dnsapi.dll",
                "httpapi.dll", "websocket.dll", "webio.dll", "qt6network.dll", "qt6websockets.dll",
                "libcurl.dll", "libcurl-x64.dll"}
PORTABLE_FLAG_TEXT = ("Game Kernel - versão portátil.\r\nCom este arquivo presente, os dados (banco, quarentena, "
                      "relatórios, configurações) ficam na pasta 'data' ao lado do programa.\r\n")


class DistributionError(Exception):
    """The distribution cannot be built safely; the message says why (pt-BR, shown to the builder)."""


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def product_version() -> str:
    """Single version source: project() in cpp/app/CMakeLists.txt (also shown by the UI and VERSIONINFO)."""
    text = (ROOT / "cpp" / "app" / "CMakeLists.txt").read_text(encoding="utf-8")
    match = re.search(r"project\(gk_app VERSION (\d+\.\d+\.\d+)", text)
    if not match:
        raise DistributionError("versão não encontrada em cpp/app/CMakeLists.txt")
    return match.group(1)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative_files(folder: Path) -> list[str]:
    return sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file())


def write_manifest(folder: Path) -> int:
    lines = [f"{sha256_file(folder / rel)}  {rel}" for rel in _relative_files(folder) if rel != MANIFEST]
    (folder / MANIFEST).write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return len(lines)


def verify_manifest(folder: Path, ignore: tuple[str, ...] = ()) -> list[str]:
    """Problems found (empty = intact). ``ignore`` lists top-level names created after installation
    (e.g. the uninstaller files or the portable data folder)."""
    manifest = folder / MANIFEST
    if not manifest.is_file():
        return [f"{MANIFEST} ausente"]
    expected: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, _, rel = line.partition("  ")
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not rel:
            return [f"linha inválida no manifesto: {line!r}"]
        expected[rel] = digest
    problems = []
    present = {rel for rel in _relative_files(folder)
               if rel != MANIFEST and rel.split("/", 1)[0] not in ignore}
    for rel, digest in sorted(expected.items()):
        if rel not in present:
            problems.append(f"ausente: {rel}")
        elif sha256_file(folder / rel) != digest:
            problems.append(f"alterado: {rel}")
    problems += [f"não previsto: {rel}" for rel in sorted(present - expected.keys())]
    return problems


def _load_public_key(path: Path) -> bytes:
    data = path.read_bytes()
    if b"PRIVATE KEY" in data:
        raise DistributionError(f"{path.name} contém uma chave PRIVADA; só a pública vai no produto")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        key = load_pem_public_key(data)
    except ValueError as exc:
        raise DistributionError(f"{path.name} não é uma chave pública PEM válida: {exc}") from None
    if not isinstance(key, Ed25519PublicKey):
        raise DistributionError(f"{path.name} não é uma chave Ed25519 (formato .gkpkg exige Ed25519)")
    return data


@dataclass
class Plan:
    out: Path
    app: Path
    bins: list[Path] = field(default_factory=list)
    helper: Path | None = None
    crt_dir: Path | None = None
    release_key: Path | None = None
    windeployqt: str | None = None
    require_core: bool = True
    deploy_qt: bool = True          # False only in tests that use stand-in binaries


def _copy_binary_with_dlls(binary: Path, out: Path, origin: dict[str, str]) -> None:
    """Copy ``binary`` and the DLLs next to it (vcpkg/Qt app-local deployment). Two different DLLs with
    the same name would silently shadow each other, so that is an error."""
    if not binary.is_file():
        raise DistributionError(f"binário não encontrado: {binary}")
    candidates = [binary] + sorted(p for p in binary.parent.glob("*.dll") if p.is_file())
    for src in candidates:
        name = src.name
        dest = out / name
        if name.lower() in NETWORK_DLLS:
            raise DistributionError(f"DLL de rede ao lado de {binary.name}: {name}")
        if dest.exists():
            if sha256_file(dest) != sha256_file(src):
                raise DistributionError(f"conflito: {name} de {src.parent} difere da copiada de {origin[name]}")
            continue
        shutil.copy2(src, dest)
        origin[name] = str(src.parent)


def _deploy_qt(exe: Path, windeployqt: str | None) -> None:
    tool = windeployqt or shutil.which("windeployqt") or shutil.which("windeployqt6")
    if sys.platform != "win32":
        return                                     # the product is Windows-only; Linux builds are for tests
    if not tool:
        raise DistributionError("windeployqt não encontrado (Qt 6 no PATH ou --windeployqt)")
    proc = subprocess.run([tool, "--release", "--no-translations", "--no-system-d3d-compiler", "--no-opengl-sw",
                           "--no-compiler-runtime", str(exe)], capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    if proc.returncode != 0:
        raise DistributionError(f"windeployqt falhou:\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}")


def _prepare_out(out: Path) -> None:
    if out.exists():
        if any(out.iterdir()) and not (out / MANIFEST).exists():
            raise DistributionError(f"{out} não está vazia e não é uma distribuição anterior; nada foi apagado")
        shutil.rmtree(out)
    out.mkdir(parents=True)


def _check(out: Path, plan: Plan) -> None:
    exe = ".exe" if plan.app.suffix.lower() == ".exe" else ""
    required = [plan.app.name, "signatures/internal/indicators.yar", "signatures/data/game_components.json",
                *RESOURCE_FILES]
    if plan.helper is not None:
        required.append(f"helper/gk-helper{exe}")
    if plan.require_core:
        required += [f"gk-cli{exe}", f"gk-scanworker{exe}", f"gk-update{exe}"]
    missing = [rel for rel in required if not (out / rel).is_file()]
    if missing:
        raise DistributionError(f"arquivos obrigatórios ausentes: {', '.join(missing)}")
    for path in out.rglob("*"):
        name = path.name.lower()
        if not path.is_file():
            continue
        if name in NETWORK_DLLS:
            raise DistributionError(f"DLL de rede na distribuição: {path.relative_to(out)}")
        if name.endswith((".key", ".gkpkg")) or name == "portable.flag":
            raise DistributionError(f"arquivo proibido na distribuição: {path.relative_to(out)}")
        if name.endswith((".pem", ".pub")) and b"PRIVATE KEY" in path.read_bytes():
            raise DistributionError(f"chave privada na distribuição: {path.relative_to(out)}")


def build(plan: Plan) -> dict:
    out = plan.out
    _prepare_out(out)
    origin: dict[str, str] = {}
    _copy_binary_with_dlls(plan.app, out, origin)
    for binary in plan.bins:
        _copy_binary_with_dlls(binary, out, origin)
    if plan.deploy_qt:
        _deploy_qt(out / plan.app.name, plan.windeployqt)
    if plan.crt_dir is not None:
        crt = sorted(plan.crt_dir.glob("*.dll"))
        if not crt:
            raise DistributionError(f"nenhuma DLL do runtime MSVC em {plan.crt_dir}")
        for dll in crt:
            shutil.copy2(dll, out / dll.name)
    if plan.helper is not None:
        if not plan.helper.is_dir():
            raise DistributionError(f"pasta do auxiliar congelado não encontrada: {plan.helper}")
        shutil.copytree(plan.helper, out / "helper")
    for sub in SIGNATURE_DIRS:
        src = ROOT / "signatures" / sub
        if src.is_dir():
            shutil.copytree(src, out / "signatures" / sub)
    for rel in RESOURCE_FILES:
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, out / rel)
    if plan.release_key is not None:
        keys = out / "signatures" / "keys"
        keys.mkdir(parents=True)
        (keys / "release.pub").write_bytes(_load_public_key(plan.release_key))
    (out / "docs").mkdir()
    for doc in DOCS:
        shutil.copy2(ROOT / "docs" / doc, out / "docs" / doc)
    _check(out, plan)
    count = write_manifest(out)
    size = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    return {"version": product_version(), "folder": str(out), "files": count, "bytes": size}


def make_portable_zip(folder: Path, zip_path: Path, top: str = "GameKernel") -> int:
    """ZIP of ``folder`` under ``top/`` plus ``top/portable.flag``; entries in a stable order."""
    problems = verify_manifest(folder)
    if problems:
        raise DistributionError("a pasta não confere com o manifesto: " + "; ".join(problems[:5]))
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = zip_path.with_suffix(zip_path.suffix + ".tmp")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        rels = _relative_files(folder)
        for rel in rels:
            zf.write(folder / rel, f"{top}/{rel}")
        zf.writestr(f"{top}/portable.flag", PORTABLE_FLAG_TEXT)
    os.replace(tmp, zip_path)
    return len(rels) + 1


def main(argv: list[str] | None = None) -> int:
    _utf8_stdio()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--app", type=Path, help="GameKernel(.exe) compilado")
    parser.add_argument("--bin", type=Path, action="append", default=[], help="gk-cli, gk-scanworker, gk-update")
    parser.add_argument("--helper", type=Path, help="pasta do gk-helper congelado (dist/gk-helper)")
    parser.add_argument("--crt-dir", type=Path, help="pasta Microsoft.VC143.CRT (implantação local do runtime MSVC)")
    parser.add_argument("--release-key", type=Path, help="chave pública Ed25519 de release (.pub)")
    parser.add_argument("--windeployqt", help="caminho do windeployqt")
    parser.add_argument("--allow-missing-core", action="store_true",
                        help="diagnóstico: aceitar distribuição sem gk-cli/gk-scanworker/gk-update")
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "GameKernel")
    parser.add_argument("--portable-zip", type=Path)
    parser.add_argument("--print-version", action="store_true")
    parser.add_argument("--verify", type=Path, metavar="PASTA", help="conferir uma pasta instalada com o manifesto")
    parser.add_argument("--ignore", action="append", default=[], help="com --verify: nome no topo a ignorar")
    args = parser.parse_args(argv)
    try:
        if args.print_version:
            print(product_version())
            return 0
        if args.verify is not None:
            problems = verify_manifest(args.verify, tuple(args.ignore))
            for p in problems:
                print(p, file=sys.stderr)
            print("íntegra" if not problems else f"{len(problems)} problema(s)")
            return 0 if not problems else 1
        if args.app is None:
            parser.error("--app é obrigatório para montar a distribuição")
        summary = build(Plan(out=args.out, app=args.app, bins=args.bin, helper=args.helper, crt_dir=args.crt_dir,
                             release_key=args.release_key, windeployqt=args.windeployqt,
                             require_core=not args.allow_missing_core))
        if args.portable_zip is not None:
            summary["portable_zip"] = str(args.portable_zip)
            summary["portable_entries"] = make_portable_zip(args.out, args.portable_zip)
    except DistributionError as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
