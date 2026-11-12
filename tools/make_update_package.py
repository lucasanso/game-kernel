"""Build, sign and verify Game Kernel offline update packages (.gkpkg).

Build (publisher machine):

    python tools/make_update_package.py build --key private/release.key --version 2026.11.12.1 \
        --publisher "Equipe Game Kernel" --yara dist/yara --ioc dist/ioc --clamav dist/clamav \
        --out GameKernel-assinaturas-2026.11.12.1.gkpkg --report relatorio-atualizacao.json

Verify (anyone, with the public key):

    python tools/make_update_package.py verify GameKernel-assinaturas-2026.11.12.1.gkpkg --keys keys/

Before signing, components are prepared and checked (gamekernel.ti): YARA rules are compiled
(without includes), IOC files are validated (conflicts, duplicates, format) — a package that
the application would reject is never produced.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gamekernel.crypto_utils import load_private_key, load_public_key, key_id  # noqa: E402
from gamekernel.updates import package as pkg  # noqa: E402


def _load_keys(dirs: list[Path]) -> dict:
    keys = {}
    for directory in dirs:
        for pub in sorted(directory.glob("*.pub")):
            key = load_public_key(pub.read_bytes())
            keys[key_id(key)] = key
    return keys


def cmd_build(args: argparse.Namespace) -> int:
    password = None
    if args.password_env:
        password = os.environ.get(args.password_env, "").encode("utf-8") or None
    elif not args.no_password:
        password = getpass.getpass("Senha da chave privada: ").encode("utf-8")
    private_key = load_private_key(args.key.read_bytes(), password)
    components = {name: getattr(args, name) for name in pkg.COMPONENTS if getattr(args, name)}
    if not components:
        print("erro: informe ao menos um componente (--yara, --ioc, --clamav)", file=sys.stderr)
        return 2
    from gamekernel.updates import prepare

    prep = prepare.check_components(components)
    if not prep.ok:
        print("erro: componentes reprovados na preparação:\n  " + "\n  ".join(prep.errors), file=sys.stderr)
        return 1
    manifest = pkg.build_package(args.out, private_key, args.version, components, publisher=args.publisher,
                                 description=args.description, min_app_version=args.min_app_version,
                                 component_meta=prep.component_meta)
    if args.report:
        report = prepare.update_report(manifest, prep, previous=args.previous, keys=_load_keys(args.keys or []))
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "package": str(args.out), "package_version": manifest["package_version"],
                      "signing_key_id": manifest["signing_key_id"], "files": len(manifest["files"]),
                      "warnings": prep.warnings}, ensure_ascii=False))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        info = pkg.verify_package(args.package, _load_keys(args.keys), args.app_version)
    except pkg.PackageError as exc:
        print(json.dumps({"ok": False, "error": {"code": exc.code, "message": str(exc)}}, ensure_ascii=False))
        return 1
    print(json.dumps({"ok": True, "key_id": info.key_id, "manifest": info.manifest}, ensure_ascii=False))
    return 0


def _utf8_stdio() -> None:
    """JSON output may contain any Unicode (paths, names): never depend on the console code page."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    _utf8_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="gera e assina um pacote")
    b.add_argument("--key", required=True, type=Path)
    b.add_argument("--no-password", action="store_true")
    b.add_argument("--password-env")
    b.add_argument("--version", required=True)
    b.add_argument("--publisher", required=True)
    b.add_argument("--description", default="")
    b.add_argument("--min-app-version", default="1.0.0")
    for name in pkg.COMPONENTS:
        b.add_argument(f"--{name}", type=Path)
    b.add_argument("--out", required=True, type=Path)
    b.add_argument("--report", type=Path, help="grava o relatório de atualização (JSON)")
    b.add_argument("--previous", type=Path, help="pacote anterior, para o relatório de diferenças")
    b.add_argument("--keys", type=Path, action="append", help="chaves públicas para verificar --previous")
    v = sub.add_parser("verify", help="verifica assinatura e integridade de um pacote")
    v.add_argument("package", type=Path)
    v.add_argument("--keys", type=Path, action="append", required=True)
    v.add_argument("--app-version", default="1.0.0")
    args = ap.parse_args(argv)
    try:
        return cmd_build(args) if args.command == "build" else cmd_verify(args)
    except pkg.PackageError as exc:
        print(json.dumps({"ok": False, "error": {"code": exc.code, "message": str(exc)}}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())
