"""Build and sign the integrity manifest of a Game Kernel installation (release step).

    python tools/build_integrity_manifest.py dist/GameKernel --version 1.0.0 --key private/release.key
    python tools/build_integrity_manifest.py dist/GameKernel --version 1.0.0 --unsigned      # local builds only

Records SHA-256 and size of every shipped file (``data/`` excluded) in ``integrity_manifest.json`` and signs its
exact bytes with the release Ed25519 key (``integrity_manifest.sig``, 64 raw bytes). At run time the application
(C++ ``gk::integrity`` and Python ``gamekernel.core.integrity``) refuses to launch a bundled binary that is
modified or unlisted. The public half of the key must be in ``signatures/keys/`` of the same build.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gamekernel.core.integrity import (MANIFEST_NAME, SIGNATURE_NAME, build_manifest,  # noqa: E402
                                       manifest_bytes)
from gamekernel.crypto_utils import key_id, load_private_key, sign  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", type=Path, help="pasta da instalação (a que contém os executáveis)")
    ap.add_argument("--version", required=True)
    key = ap.add_mutually_exclusive_group(required=True)
    key.add_argument("--key", type=Path, help="chave privada Ed25519 (PKCS#8)")
    key.add_argument("--unsigned", action="store_true", help="sem assinatura (builds locais; o app avisa)")
    ap.add_argument("--no-password", action="store_true", help="chave privada sem senha (testes)")
    ap.add_argument("--password-env", help="lê a senha desta variável de ambiente (automação)")
    args = ap.parse_args(argv)

    root = args.root.resolve()
    if not root.is_dir():
        print(f"erro: {root} não é uma pasta", file=sys.stderr)
        return 1
    for stale in (root / MANIFEST_NAME, root / SIGNATURE_NAME):
        stale.unlink(missing_ok=True)

    signer = None
    if args.key:
        password: bytes | None = None
        if args.password_env:
            password = os.environ.get(args.password_env, "").encode("utf-8") or None
        elif not args.no_password:
            password = getpass.getpass("Senha da chave privada: ").encode("utf-8")
        signer = load_private_key(args.key.read_bytes(), password)

    manifest = build_manifest(root, args.version)
    raw = manifest_bytes(manifest)
    (root / MANIFEST_NAME).write_bytes(raw)
    if signer is not None:
        (root / SIGNATURE_NAME).write_bytes(sign(signer, raw))
        print(f"{len(manifest['files'])} arquivos; manifesto assinado pela chave {key_id(signer.public_key())}")
    else:
        print(f"{len(manifest['files'])} arquivos; manifesto SEM assinatura (somente para builds locais)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
