"""``.gkpkg`` v1 — signed offline update packages (publisher side + reference verifier).

The *installation* inside the application is done by the C++ core (``cpp/updates``); this
module builds and signs packages (publisher tools) and contains an independent reference
verifier used by ``tools/make_update_package.py verify`` and by the equivalence tests that
compare the Python and C++ implementations.

Layout (all integers little-endian)::

    offset 0   magic        8 bytes   b"GKPKG\\x00" + format_version(u8)=1 + reserved(u8)=0
    offset 8   manifest_len u32       1 .. MAX_MANIFEST
    offset 12  manifest     JSON (UTF-8), see below
    ...        sig_len      u32       = 64
    ...        signature    Ed25519 over  magic || manifest_len || manifest
    ...        payloads     the files, concatenated in manifest order, exact sizes, nothing after

Why not ZIP: no archive parser, no decompression (no bombs), no paths taken from archive
metadata, single-pass streaming verification in C++.

Manifest (``gamekernel-update`` v1)::

    {"format": "gamekernel-update", "format_version": 1, "package_id": "<uuid4>",
     "package_version": "2026.11.12.1", "created_at": "2026-11-12T10:00:00Z", "publisher": "...",
     "description": "...", "min_app_version": "1.0.0",
     "components": {"yara": {"version": "...", "rule_count": 42}, "ioc": {...}, "clamav": {...}},
     "files": [{"path": "yara/rules.yar", "size": 123, "sha256": "<64 hex>"}],
     "signing_key_id": "<16 hex>"}

A component listed in a package **replaces** the installed component; components not listed
are kept. Versions are monotonic: older or equal ``package_version`` is refused unless the user
explicitly allows a downgrade.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import struct
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .. import __version__
from ..crypto_utils import key_id

MAGIC = b"GKPKG\x00\x01\x00"
FORMAT = "gamekernel-update"
FORMAT_VERSION = 1
SIG_LEN = 64
MAX_MANIFEST = 1024 * 1024
MAX_FILES = 512
MAX_FILE_SIZE = 1024 * 1024 * 1024          # 1 GiB per file (main.cvd is ~170 MB)
MAX_TOTAL = 4 * 1024 * 1024 * 1024          # 4 GiB per package
CHUNK = 1024 * 1024

COMPONENTS = ("clamav", "yara", "ioc")
EXTENSIONS = {
    "clamav": {".cvd", ".cld", ".cud", ".hdb", ".hsb", ".ndb", ".ldb", ".cdb", ".ign2", ".fp", ".sfp"},
    "yara": {".yar", ".yara"},
    "ioc": {".json"},
}
# Always used with fullmatch(): ``$`` would accept a trailing newline.
PATH_RE = re.compile(r"(clamav|yara|ioc)/[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
VERSION_RE = re.compile(r"\d{4}\.\d{1,2}\.\d{1,2}(\.\d{1,4})?")
APP_VERSION_RE = re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,4}")
SHA_RE = re.compile(r"[0-9a-f]{64}")
KEY_ID_RE = re.compile(r"[0-9a-f]{16}")
RESERVED_RE = re.compile(r"(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?", re.IGNORECASE)   # Windows devices
REQUIRED_FIELDS = ("format", "format_version", "package_id", "package_version", "created_at", "publisher",
                   "min_app_version", "components", "files", "signing_key_id")


class PackageError(Exception):
    """The package is invalid, tampered, untrusted or incompatible.

    ``code`` is stable and identical in the C++ verifier (gk::updates::ErrorCode):
    not_a_package, unsupported_format, invalid_header, truncated, no_trusted_keys, bad_signature,
    invalid_manifest, incompatible_app, hash_mismatch, trailing_data, downgrade, validation_failed, io_error.
    """

    def __init__(self, message: str, code: str = "invalid_manifest"):
        super().__init__(message)
        self.code = code


@dataclass
class PackageInfo:
    path: Path
    manifest: dict
    key_id: str
    payload_offset: int
    files: list[dict] = field(default_factory=list)


def _as_int(value: object) -> int | None:
    """JSON integer rule shared with the C++ verifier (Qt does not distinguish 1 from 1.0):
    an integral number is accepted, booleans and fractions are not."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer() and abs(value) <= 2**53:
        return int(value)
    return None


def version_tuple(version: str) -> tuple[int, ...]:
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise PackageError(f"versão de pacote inválida: {version!r}")
    parts = tuple(int(p) for p in version.split("."))
    return parts + (0,) * (4 - len(parts))


def app_version_tuple(version: str) -> tuple[int, int, int]:
    if not isinstance(version, str) or not APP_VERSION_RE.fullmatch(version):
        raise PackageError(f"versão de aplicativo inválida: {version!r}")
    a, b, c = (int(p) for p in version.split("."))
    return a, b, c


def validate_manifest(manifest: object, app_version: str | None = None) -> list[str]:
    """Return a list of problems (empty = valid). Mirrors gk::updates::validateManifest (C++).

    ``app_version`` adds the compatibility check (min_app_version); read_header checks it
    separately to report ``incompatible_app``.
    """
    if not isinstance(manifest, dict):
        return ["o manifesto precisa ser um objeto JSON"]
    errors = [f"campo obrigatório ausente: {k}" for k in REQUIRED_FIELDS if k not in manifest]
    if errors:
        return errors
    if manifest["format"] != FORMAT or _as_int(manifest["format_version"]) != FORMAT_VERSION:
        errors.append("formato de pacote não suportado")
    for key in ("package_id", "created_at", "publisher", "min_app_version", "package_version", "signing_key_id"):
        if not isinstance(manifest[key], str) or not manifest[key]:
            errors.append(f"campo '{key}' precisa ser texto não vazio")
    if errors:
        return errors
    try:
        version_tuple(manifest["package_version"])
    except PackageError as exc:
        errors.append(str(exc))
    try:
        minimum = app_version_tuple(manifest["min_app_version"])
        if app_version is not None and minimum > app_version_tuple(app_version):
            errors.append(f"pacote exige o Game Kernel {manifest['min_app_version']} ou mais novo "
                          f"(instalado: {app_version})")
    except PackageError as exc:
        errors.append(str(exc))
    if not KEY_ID_RE.fullmatch(manifest["signing_key_id"]):
        errors.append("signing_key_id inválido")
    components = manifest["components"]
    if not isinstance(components, dict) or not components:
        errors.append("o pacote precisa declarar ao menos um componente")
        components = {}
    for name, meta in components.items():
        if name not in COMPONENTS:
            errors.append(f"componente desconhecido: {name}")
        elif not isinstance(meta, dict) or not isinstance(meta.get("version"), str) or not meta["version"]:
            errors.append(f"componente {name} sem versão")
    files = manifest["files"]
    if not isinstance(files, list) or not files:
        return errors + ["o pacote não contém arquivos"]
    if len(files) > MAX_FILES:
        errors.append(f"arquivos demais ({len(files)} > {MAX_FILES})")
    seen: set[str] = set()
    total = 0
    used_components: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            errors.append("entrada de arquivo inválida")
            continue
        path, size, digest = entry.get("path"), entry.get("size"), entry.get("sha256")
        if not isinstance(path, str) or not PATH_RE.fullmatch(path) or ".." in path:
            errors.append(f"caminho não permitido: {path!r}")
            continue
        component, name = path.split("/", 1)
        if os.path.splitext(name)[1].lower() not in EXTENSIONS[component]:
            errors.append(f"extensão não permitida em {component}: {path}")
        if RESERVED_RE.fullmatch(name):
            errors.append(f"nome reservado do Windows: {path}")
        if path.lower() in seen:
            errors.append(f"arquivo duplicado: {path}")
        seen.add(path.lower())
        size = _as_int(size)
        if size is None or not (0 <= size <= MAX_FILE_SIZE):
            errors.append(f"tamanho inválido para {path}")
        else:
            total += size
            entry["size"] = size
        if not isinstance(digest, str) or not SHA_RE.fullmatch(digest):
            errors.append(f"sha256 inválido para {path}")
        if component not in components:
            errors.append(f"arquivo {path} pertence a um componente não declarado")
        used_components.add(component)
    for name in components:
        if name not in used_components:
            errors.append(f"componente {name} declarado sem arquivos")
    if total > MAX_TOTAL:
        errors.append("tamanho total do pacote acima do limite")
    return errors


# ---------------------------------------------------------------------------- building (publisher)
def _collect(component: str, directory: Path) -> list[tuple[str, Path]]:
    if not directory.is_dir():
        raise PackageError(f"pasta do componente {component} não existe: {directory}", "io_error")
    out = []
    for item in sorted(directory.iterdir(), key=lambda p: p.name.lower()):
        if item.is_symlink():
            raise PackageError(f"links simbólicos não são aceitos: {item}")
        if item.is_dir():
            raise PackageError(f"subpastas não são aceitas em {component}: {item.name}")
        rel = f"{component}/{item.name}"
        if not PATH_RE.fullmatch(rel) or item.suffix.lower() not in EXTENSIONS[component]:
            raise PackageError(f"arquivo não permitido no componente {component}: {item.name}")
        out.append((rel, item))
    if not out:
        raise PackageError(f"componente {component} está vazio")
    return out


def _sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def signed_prefix(manifest_bytes: bytes) -> bytes:
    return MAGIC + struct.pack("<I", len(manifest_bytes)) + manifest_bytes


def build_package(output: str | os.PathLike, private_key: Ed25519PrivateKey, package_version: str,
                  components: dict[str, str | os.PathLike], *, publisher: str, description: str = "",
                  min_app_version: str = "1.0.0", component_meta: dict[str, dict] | None = None,
                  created_at: str | None = None) -> dict:
    """Build and sign a package. Returns the manifest."""
    if not components:
        raise PackageError("nenhum componente informado")
    unknown = set(components) - set(COMPONENTS)
    if unknown:
        raise PackageError(f"componentes desconhecidos: {sorted(unknown)}")
    files: list[tuple[str, Path, str, int]] = []
    comp_entries: dict[str, dict] = {}
    for name in COMPONENTS:
        if name not in components:
            continue
        for rel, path in _collect(name, Path(components[name])):
            digest, size = _sha256_file(path)
            files.append((rel, path, digest, size))
        meta = dict((component_meta or {}).get(name, {}))
        meta.setdefault("version", package_version)
        comp_entries[name] = meta
    manifest = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "package_id": str(uuid.uuid4()),
        "package_version": package_version,
        "created_at": created_at or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "publisher": publisher,
        "description": description,
        "min_app_version": min_app_version,
        "components": comp_entries,
        "files": [{"path": rel, "size": size, "sha256": digest} for rel, _, digest, size in files],
        "signing_key_id": key_id(private_key.public_key()),
    }
    problems = validate_manifest(manifest)
    if problems:
        raise PackageError("; ".join(problems), "invalid_manifest")
    manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8")
    if len(manifest_bytes) > MAX_MANIFEST:
        raise PackageError("manifesto grande demais", "invalid_header")
    signature = private_key.sign(signed_prefix(manifest_bytes))
    out = Path(output)
    fd, tmp = tempfile.mkstemp(prefix=".gkpkg-", dir=str(out.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(signed_prefix(manifest_bytes))
            fh.write(struct.pack("<I", SIG_LEN))
            fh.write(signature)
            for rel, path, digest, size in files:
                h = hashlib.sha256()
                written = 0
                with path.open("rb") as src:
                    while chunk := src.read(CHUNK):
                        h.update(chunk)
                        written += len(chunk)
                        fh.write(chunk)
                if h.hexdigest() != digest or written != size:
                    raise PackageError(f"{path} mudou durante a geração do pacote", "io_error")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, out)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return manifest


# ---------------------------------------------------------------------------- reference verifier
def _read_exact(fh: BinaryIO, n: int, what: str) -> bytes:
    data = fh.read(n)
    if len(data) != n:
        raise PackageError(f"pacote truncado ({what})", "truncated")
    return data


def read_header(fh: BinaryIO, keys: dict[str, Ed25519PublicKey], app_version: str = __version__) -> tuple[dict, str]:
    """Read and authenticate the header. Returns (manifest, key_id). Nothing is trusted before this."""
    magic = _read_exact(fh, 8, "assinatura do formato")
    if magic[:6] != MAGIC[:6]:
        raise PackageError("não é um pacote do Game Kernel (.gkpkg)", "not_a_package")
    if magic != MAGIC:
        raise PackageError(f"versão de formato não suportada: {magic[6]}", "unsupported_format")
    (manifest_len,) = struct.unpack("<I", _read_exact(fh, 4, "tamanho do manifesto"))
    if not 1 <= manifest_len <= MAX_MANIFEST:
        raise PackageError("tamanho de manifesto inválido", "invalid_header")
    manifest_bytes = _read_exact(fh, manifest_len, "manifesto")
    (sig_len,) = struct.unpack("<I", _read_exact(fh, 4, "tamanho da assinatura"))
    if sig_len != SIG_LEN:
        raise PackageError("tamanho de assinatura inválido", "invalid_header")
    signature = _read_exact(fh, SIG_LEN, "assinatura")
    if not keys:
        raise PackageError("nenhuma chave pública confiável está instalada", "no_trusted_keys")
    signer = None
    for kid, key in keys.items():
        try:
            key.verify(signature, signed_prefix(manifest_bytes))
            signer = kid
            break
        except InvalidSignature:
            continue
    if signer is None:
        raise PackageError("assinatura inválida ou feita por uma chave não confiável", "bad_signature")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise PackageError(f"manifesto ilegível: {exc}", "invalid_manifest") from None
    problems = validate_manifest(manifest)
    if problems:
        raise PackageError("; ".join(problems), "invalid_manifest")
    if app_version_tuple(manifest["min_app_version"]) > app_version_tuple(app_version):
        raise PackageError(f"pacote exige o Game Kernel {manifest['min_app_version']} ou mais novo "
                           f"(instalado: {app_version})", "incompatible_app")
    return manifest, signer


def _reject_constant(name: str):
    raise ValueError(f"constante não permitida: {name}")


def verify_package(path: str | os.PathLike, keys: dict[str, Ed25519PublicKey],
                   app_version: str = __version__, extract_to: str | os.PathLike | None = None) -> PackageInfo:
    """Fully verify a package (signature, manifest, every payload hash, no trailing data).

    With ``extract_to`` the payloads are also written there (``<dir>/<component>/<name>``).
    """
    path = Path(path)
    with path.open("rb") as fh:
        manifest, signer = read_header(fh, keys, app_version)
        offset = fh.tell()
        for entry in manifest["files"]:
            h = hashlib.sha256()
            remaining = entry["size"]
            out = None
            if extract_to is not None:
                target = Path(extract_to) / entry["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                out = target.open("wb")
            try:
                while remaining:
                    chunk = fh.read(min(CHUNK, remaining))
                    if not chunk:
                        raise PackageError(f"pacote truncado em {entry['path']}", "truncated")
                    h.update(chunk)
                    if out:
                        out.write(chunk)
                    remaining -= len(chunk)
            finally:
                if out:
                    out.close()
            if h.hexdigest() != entry["sha256"]:
                raise PackageError(f"conteúdo adulterado: hash de {entry['path']} não confere", "hash_mismatch")
        if fh.read(1):
            raise PackageError("dados extras após o último arquivo", "trailing_data")
    return PackageInfo(path, manifest, signer, offset, manifest["files"])
