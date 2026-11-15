#!/usr/bin/env python3
"""Sign a Game Kernel release without the private key ever leaving the publisher's computer.

The CI builds the product and prepares the release folder with the release *public* key
(tools/make_distribution.py --public-key): it ships signatures/keys/release.pub and an unsigned
integrity_manifest.json. The manifest is then signed here, on the publisher's computer, and the 64-byte
signature — which is not secret — goes back to the CI, which attaches it to that very folder (no rebuild,
so the hashes stay the same), builds the installer and the portable ZIP and tests the installed product.

    # on your computer, in the folder of the downloaded "gamekernel-release-manifesto" artifact:
    python tools/release_sign.py sign integrity_manifest.json --key E:\\chaves-game-kernel\\release.key
    #   -> integrity_manifest.sig and assinatura.json (commit it as installer/release/assinatura.json)

    # in CI (or locally), on the prepared folder:
    python tools/release_sign.py attach dist/release/GameKernel --signature installer/release/assinatura.json \\
        --expect-key installer/release/release.pub --portable-zip dist/final/GameKernel-<versão>-portable.zip

`sign` refuses a manifest that does not ship the public half of the key being used (the CI was prepared with
another key) and shows what is being signed before asking for confirmation. `attach` refuses a signature that
does not verify, a folder that does not match its manifest and, with --expect-key, a folder that ships another
key.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gamekernel import crypto_utils  # noqa: E402
from gamekernel.core.integrity import MANIFEST_NAME, SIGNATURE_NAME  # noqa: E402
from tools import make_distribution as MD  # noqa: E402

PREPARATION_NAME = "preparo.json"     # written by the CI next to the manifest artifact (version, run id, key id)
RECORD_NAME = "assinatura.json"       # what goes back to the repository: installer/release/assinatura.json


class ReleaseError(Exception):
    """The release cannot be signed or finished; the message says why (pt-BR)."""


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def _load_manifest(raw: bytes) -> dict:
    try:
        manifest = json.loads(raw)
    except ValueError as exc:
        raise ReleaseError(f"o manifesto não é JSON válido: {exc}") from None
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict) or not manifest["files"]:
        raise ReleaseError("o arquivo não é um manifesto de integridade do Game Kernel")
    return manifest


def sign_manifest(manifest_path: Path, key_path: Path, password: bytes | None, confirm=None) -> dict:
    """Sign ``manifest_path`` with the private key; returns the record written to assinatura.json."""
    raw = manifest_path.read_bytes()
    manifest = _load_manifest(raw)
    try:
        private = crypto_utils.load_private_key(key_path.read_bytes(), password)
    except (OSError, ValueError, TypeError) as exc:
        raise ReleaseError(f"não foi possível abrir a chave privada {key_path.name} (senha errada?): {exc}") from None
    public = private.public_key()
    kid = crypto_utils.key_id(public)
    pem = MD.public_pem(public)
    shipped = manifest["files"].get(MD.RELEASE_PUB)
    if not isinstance(shipped, dict) or shipped.get("sha256") != hashlib.sha256(pem).hexdigest():
        raise ReleaseError("esta versão não leva a chave pública desta chave privada (a CI foi preparada com outra "
                           f"chave, ou falta {MD.RELEASE_PUB}); nada foi assinado")
    preparation = {}
    prep_path = manifest_path.with_name(PREPARATION_NAME)
    if prep_path.is_file():
        preparation = json.loads(prep_path.read_text(encoding="utf-8"))
    total = sum(int(entry.get("size", 0)) for entry in manifest["files"].values() if isinstance(entry, dict))
    summary = {
        "versao": manifest.get("version", ""),
        "arquivos": len(manifest["files"]),
        "bytes": total,
        "chave": kid,
        "manifesto_sha256": hashlib.sha256(raw).hexdigest(),
        "execucao": preparation.get("execucao"),
        "commit": preparation.get("commit"),
    }
    if confirm is not None and not confirm(summary):
        raise ReleaseError("assinatura cancelada")
    signature = crypto_utils.sign(private, raw)
    manifest_path.with_name(SIGNATURE_NAME).write_bytes(signature)
    record = dict(summary, assinatura=base64.b64encode(signature).decode("ascii"))
    manifest_path.with_name(RECORD_NAME).write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n",
                                                    encoding="utf-8")
    return record


def _signature_bytes(value: str) -> bytes:
    """A signature given as assinatura.json, a raw .sig file or base64 text."""
    path = Path(value)
    if len(value) < 4096 and path.is_file():
        data = path.read_bytes()
        if path.suffix.lower() == ".json":
            try:
                value = json.loads(data)["assinatura"]
            except (ValueError, KeyError, TypeError):
                raise ReleaseError(f"{path.name} não contém o campo 'assinatura'") from None
        elif len(data) == 64:
            return data
        else:
            value = data.decode("ascii", errors="replace").strip()
    try:
        signature = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise ReleaseError("a assinatura não é base64 válido") from None
    if len(signature) != 64:
        raise ReleaseError(f"a assinatura tem {len(signature)} bytes; uma assinatura Ed25519 tem 64")
    return signature


def attach_signature(folder: Path, signature_value: str, expect_key: Path | None = None,
                     portable_zip: Path | None = None) -> dict:
    """Put the signature next to the manifest of the prepared folder and check everything."""
    manifest_path = folder / MANIFEST_NAME
    if not manifest_path.is_file():
        raise ReleaseError(f"{MANIFEST_NAME} não encontrado em {folder}")
    manifest = _load_manifest(manifest_path.read_bytes())
    pub_path = folder / MD.RELEASE_PUB
    if not pub_path.is_file():
        raise ReleaseError(f"a pasta não leva {MD.RELEASE_PUB}")
    shipped = crypto_utils.load_public_key(pub_path.read_bytes())
    kid = crypto_utils.key_id(shipped)
    if expect_key is not None:
        expected = crypto_utils.key_id(crypto_utils.load_public_key(expect_key.read_bytes()))
        if expected != kid:
            raise ReleaseError(f"a pasta leva a chave {kid}, não a chave de release esperada {expected}")
    signature = _signature_bytes(signature_value)
    sig_path = folder / SIGNATURE_NAME
    sig_path.write_bytes(signature)
    problems = MD.manifest_problems(folder)
    if problems:
        sig_path.unlink(missing_ok=True)
        raise ReleaseError("a versão não foi finalizada: " + "; ".join(problems[:5]))
    result = {"versao": manifest.get("version", ""), "chave": kid, "arquivos": len(manifest["files"]),
              "pasta": str(folder)}
    if portable_zip is not None:
        result["portatil"] = str(portable_zip)
        result["portatil_entradas"] = MD.make_portable_zip(folder, portable_zip)
    return result


def _ask(summary: dict) -> bool:
    mib = summary["bytes"] / (1024 * 1024)
    print("Versão a assinar:")
    print(f"  versão ............ {summary['versao']}")
    print(f"  arquivos .......... {summary['arquivos']} ({mib:.1f} MB)")
    print(f"  chave de release .. {summary['chave']}")
    if summary.get("execucao"):
        print(f"  execução da CI .... {summary['execucao']} (commit {str(summary.get('commit') or '')[:12]})")
    print(f"  manifesto SHA-256 . {summary['manifesto_sha256']}")
    return input("Assinar esta versão? [s/N] ").strip().lower() in ("s", "sim", "y", "yes")


def main(argv: list[str] | None = None) -> int:
    _utf8_stdio()
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("sign", help="assina o manifesto (no seu computador, com a chave privada)")
    s.add_argument("manifest", type=Path)
    s.add_argument("--key", type=Path, required=True)
    s.add_argument("--password-env", help="lê a senha desta variável de ambiente (automação)")
    s.add_argument("--no-password", action="store_true", help="chave sem senha (somente testes)")
    s.add_argument("--yes", action="store_true", help="não pede confirmação")
    a = sub.add_parser("attach", help="anexa a assinatura à pasta preparada e confere (CI)")
    a.add_argument("folder", type=Path)
    a.add_argument("--signature", required=True, help="assinatura.json, arquivo .sig ou texto base64")
    a.add_argument("--expect-key", type=Path, help="chave pública que a pasta precisa levar")
    a.add_argument("--portable-zip", type=Path)
    k = sub.add_parser("key-id", help="identificador de uma chave pública (o que o programa mostra)")
    k.add_argument("public_key", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "key-id":
            try:
                print(crypto_utils.key_id(crypto_utils.load_public_key(args.public_key.read_bytes())))
            except (OSError, ValueError, TypeError) as exc:
                raise ReleaseError(f"{args.public_key} não é uma chave pública Ed25519: {exc}") from None
            return 0
        if args.command == "sign":
            password = None
            if args.password_env:
                password = os.environ.get(args.password_env, "").encode("utf-8") or None
            elif not args.no_password:
                password = getpass.getpass("Senha da chave privada: ").encode("utf-8")
            record = sign_manifest(args.manifest, args.key, password, confirm=None if args.yes else _ask)
            print(json.dumps(record, ensure_ascii=False, indent=2))
            print(f"\nAssinado. Envie {RECORD_NAME} (não é segredo) para installer/release/{RECORD_NAME} no repositório.")
        else:
            print(json.dumps(attach_signature(args.folder, args.signature, args.expect_key, args.portable_zip),
                             ensure_ascii=False, indent=2))
    except (ReleaseError, MD.DistributionError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
