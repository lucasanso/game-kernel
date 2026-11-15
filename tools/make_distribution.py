#!/usr/bin/env python3
"""Assemble the Game Kernel product folder, sign its integrity manifest and build the portable ZIP.

The folder is what the Windows installer (installer/gamekernel.iss) copies to Program Files and what the
portable ZIP contains:

    GameKernel.exe, Qt runtime (windeployqt), gk-cli.exe, gk-scanworker.exe, gk-update.exe, MSVC runtime
    helper/                    frozen gk-helper (PyInstaller one-folder)
    signatures/                bundled YARA, indicators, IOC, ClamAV, component data and keys/release.pub
    contracts/                 threat_catalog.json (explanations and recommendations of the risk engine)
    docs/                      USAGE, PRIVACY, LIMITATIONS
    integrity_manifest.json    SHA-256 and size of every shipped file (Agent A's gk::integrity format, M10),
    integrity_manifest.sig     signed with the release key; the core refuses to launch a modified or unlisted
                               bundled binary, and `gk-cli integrity` re-checks the whole installation

The manifest is produced with Agent A's code (gamekernel.core.integrity, the same as
tools/build_integrity_manifest.py) as the very last step, and the public half of the signing key is shipped in
signatures/keys/release.pub, so the two can never disagree.

Safety checks (the build fails instead of shipping something wrong): required files present, no private key
material, no networking DLL, no conflicting DLLs with the same name, no portable.flag in the installed folder,
manifest consistent with the folder before the ZIP is written. The portable ZIP is the same folder plus
``portable.flag`` (data then lives in ``<folder>/data``, which the manifest excludes).

Usage (Windows CI, see .github/workflows/ci.yml):
    python tools/make_distribution.py --app <GameKernel.exe> --bin <gk-cli.exe> --bin <gk-scanworker.exe> \
        --bin <gk-update.exe> --helper dist/gk-helper --crt-dir <Microsoft.VC143.CRT> \
        --key <release private key> [--password-env VAR | --no-password] \
        --out dist/GameKernel --portable-zip dist/GameKernel-<versão>-portable.zip
    (--unsigned instead of --key only for local builds: the application then reports an unsigned manifest)
    python tools/make_distribution.py --print-version
"""

from __future__ import annotations

import argparse
import getpass
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
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from gamekernel import crypto_utils  # noqa: E402
from gamekernel.core.integrity import MANIFEST_NAME, SIGNATURE_NAME, build_manifest, manifest_bytes  # noqa: E402

SIGNATURE_DIRS = ("yara", "internal", "ioc", "clamav", "data")
# Data files the core loads at run time from its resource folder (cpp/scan Config): missing ones degrade
# the analysis, so they are copied and required explicitly.
RESOURCE_FILES = ("contracts/threat_catalog.json",)
DOCS = ("USAGE.md", "PRIVACY.md", "LIMITATIONS.md")
RELEASE_PUB = "signatures/keys/release.pub"
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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_signing_key(path: Path, password: bytes | None) -> Ed25519PrivateKey:
    try:
        return crypto_utils.load_private_key(path.read_bytes(), password)
    except (ValueError, TypeError) as exc:
        raise DistributionError(f"{path.name} não é uma chave privada Ed25519 utilizável: {exc}") from None


@dataclass
class Plan:
    out: Path
    app: Path
    bins: list[Path] = field(default_factory=list)
    helper: Path | None = None
    crt_dir: Path | None = None
    signer: Ed25519PrivateKey | None = None   # None = unsigned manifest (local builds only)
    windeployqt: str | None = None
    require_core: bool = True
    deploy_qt: bool = True                    # False only in tests that use stand-in binaries


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
            if _sha256(dest) != _sha256(src):
                raise DistributionError(f"conflito: {name} de {src.parent} difere da copiada de {origin[name]}")
            continue
        shutil.copy2(src, dest)
        origin[name] = str(src.parent)


def _deploy_qt(exe: Path, windeployqt: str | None) -> None:
    if sys.platform != "win32":
        return                                     # the product is Windows-only; Linux builds are for tests
    tool = windeployqt or shutil.which("windeployqt") or shutil.which("windeployqt6")
    if not tool:
        raise DistributionError("windeployqt não encontrado (Qt 6 no PATH ou --windeployqt)")
    # --skip-plugin-types generic: Qt's "generic" input plugins (TUIO touch over UDP) need Qt6Network, which
    # would otherwise be deployed although the application never loads it (found by the assembly check).
    proc = subprocess.run([tool, "--release", "--no-translations", "--no-system-d3d-compiler", "--no-opengl-sw",
                           "--no-compiler-runtime", "--skip-plugin-types", "generic", str(exe)],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise DistributionError(f"windeployqt falhou:\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}")


def _prepare_out(out: Path) -> None:
    if out.exists():
        if any(out.iterdir()) and not (out / MANIFEST_NAME).exists():
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


def sign_installation(out: Path, version: str, signer: Ed25519PrivateKey | None) -> int:
    """Write (and sign) the integrity manifest with Agent A's code; the last step of the assembly."""
    raw = manifest_bytes(build_manifest(out, version))
    (out / MANIFEST_NAME).write_bytes(raw)
    if signer is not None:
        (out / SIGNATURE_NAME).write_bytes(crypto_utils.sign(signer, raw))
    return len(json.loads(raw)["files"])


def manifest_problems(out: Path) -> list[str]:
    """Consistency of the folder with its manifest (before zipping, and in tests): same files, sizes and
    hashes as a fresh manifest, and a signature that verifies with the key shipped in the folder."""
    path = out / MANIFEST_NAME
    if not path.is_file():
        return [f"{MANIFEST_NAME} ausente"]
    raw = path.read_bytes()
    stored = json.loads(raw).get("files", {})
    fresh = build_manifest(out, "")["files"]
    problems = [f"ausente: {rel}" for rel in sorted(stored.keys() - fresh.keys())]
    problems += [f"alterado: {rel}" for rel in sorted(stored.keys() & fresh.keys()) if stored[rel] != fresh[rel]]
    problems += [f"não previsto: {rel}" for rel in sorted(fresh.keys() - stored.keys())]
    sig = out / SIGNATURE_NAME
    if sig.is_file():
        keys = {}
        for pub in sorted((out / "signatures" / "keys").glob("*.pub")):
            key = crypto_utils.load_public_key(pub.read_bytes())
            keys[crypto_utils.key_id(key)] = key
        if crypto_utils.verify(raw, sig.read_bytes(), keys) is None:
            problems.append("assinatura do manifesto não confere com as chaves distribuídas")
    return problems


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
    key_id = None
    if plan.signer is not None:
        public = plan.signer.public_key()
        (out / RELEASE_PUB).parent.mkdir(parents=True, exist_ok=True)
        (out / RELEASE_PUB).write_bytes(public.public_bytes(serialization.Encoding.PEM,
                                                            serialization.PublicFormat.SubjectPublicKeyInfo))
        key_id = crypto_utils.key_id(public)
    (out / "docs").mkdir()
    for doc in DOCS:
        shutil.copy2(ROOT / "docs" / doc, out / "docs" / doc)
    _check(out, plan)
    version = product_version()
    count = sign_installation(out, version, plan.signer)
    size = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    return {"version": version, "folder": str(out), "files": count, "bytes": size,
            "signed": plan.signer is not None, "key_id": key_id}


def make_portable_zip(folder: Path, zip_path: Path, top: str = "GameKernel") -> int:
    """ZIP of ``folder`` under ``top/`` plus ``top/portable.flag``; entries in a stable order."""
    problems = manifest_problems(folder)
    if problems:
        raise DistributionError("a pasta não confere com o manifesto: " + "; ".join(problems[:5]))
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = zip_path.with_suffix(zip_path.suffix + ".tmp")
    rels = sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file())
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
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
    signing = parser.add_mutually_exclusive_group()
    signing.add_argument("--key", type=Path, help="chave privada Ed25519 de release (assina o manifesto)")
    signing.add_argument("--unsigned", action="store_true", help="manifesto sem assinatura (somente builds locais)")
    parser.add_argument("--no-password", action="store_true", help="chave privada sem senha (CI com chave efêmera)")
    parser.add_argument("--password-env", help="lê a senha da chave desta variável de ambiente")
    parser.add_argument("--windeployqt", help="caminho do windeployqt")
    parser.add_argument("--allow-missing-core", action="store_true",
                        help="diagnóstico: aceitar distribuição sem gk-cli/gk-scanworker/gk-update")
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "GameKernel")
    parser.add_argument("--portable-zip", type=Path)
    parser.add_argument("--print-version", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.print_version:
            print(product_version())
            return 0
        if args.app is None:
            parser.error("--app é obrigatório para montar a distribuição")
        if not args.key and not args.unsigned:
            parser.error("escolha --key <chave de release> ou, só para builds locais, --unsigned")
        signer = None
        if args.key:
            password = None
            if args.password_env:
                password = os.environ.get(args.password_env, "").encode("utf-8") or None
            elif not args.no_password:
                password = getpass.getpass("Senha da chave privada: ").encode("utf-8")
            signer = load_signing_key(args.key, password)
        summary = build(Plan(out=args.out, app=args.app, bins=args.bin, helper=args.helper, crt_dir=args.crt_dir,
                             signer=signer, windeployqt=args.windeployqt, require_core=not args.allow_missing_core))
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
