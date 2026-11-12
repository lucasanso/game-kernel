"""Generate the Ed25519 key pair used to sign Game Kernel offline update packages.

    python tools/gk_keygen.py --out-dir private --name release

Writes ``<name>.key`` (PKCS#8, encrypted with a password unless --no-password; permission 600)
and ``<name>.pub`` (distribute this one: it goes to ``signatures/keys/`` of the build or is
added by the user in the Offline Update Center). Never commit the private key.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gamekernel.crypto_utils import generate_keypair, key_id, load_public_key  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--name", default="release")
    ap.add_argument("--no-password", action="store_true", help="chave privada sem senha (apenas para testes)")
    ap.add_argument("--password-env", help="lê a senha desta variável de ambiente (automação)")
    args = ap.parse_args(argv)

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    private_path, public_path = out / f"{args.name}.key", out / f"{args.name}.pub"
    for path in (private_path, public_path):
        if path.exists():
            print(f"erro: {path} já existe; não sobrescrevo chaves", file=sys.stderr)
            return 1
    password: bytes | None = None
    if args.password_env:
        value = os.environ.get(args.password_env)
        if not value:
            print(f"erro: variável {args.password_env} vazia", file=sys.stderr)
            return 1
        password = value.encode("utf-8")
    elif not args.no_password:
        first = getpass.getpass("Senha da chave privada: ")
        if len(first) < 12 or first != getpass.getpass("Repita a senha: "):
            print("erro: senhas diferentes ou com menos de 12 caracteres", file=sys.stderr)
            return 1
        password = first.encode("utf-8")

    private_pem, public_pem = generate_keypair(password)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(private_pem)
    public_path.write_bytes(public_pem)
    kid = key_id(load_public_key(public_pem))
    print(f"chave privada: {private_path}\nchave pública: {public_path}\nidentificador: {kid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
