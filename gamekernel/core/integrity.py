"""Self-integrity of the installation.

At build time ``tools/build_integrity_manifest.py`` records the SHA-256 of every shipped
file in ``integrity_manifest.json`` and signs it with the release Ed25519 key
(``integrity_manifest.sig``). At run time:

* ``check_installation()`` re-hashes every listed file (Dashboard / Privacy page).
* ``verify_component(path)`` is called before launching a bundled helper binary
  (clamscan, sigtool, 7z): a modified binary is never executed.

In a development checkout there is no manifest; results then say so explicitly instead of
pretending the installation was verified.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .. import app_paths, crypto_utils
from .hashing import sha256_file

MANIFEST_NAME = "integrity_manifest.json"
SIGNATURE_NAME = "integrity_manifest.sig"
FORMAT = "gamekernel-integrity"


@dataclass
class IntegrityReport:
    ok: bool
    manifest_present: bool
    signature_valid: bool | None
    signer_key_id: str | None
    verified: int = 0
    missing: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    detail: str = ""
    checked_at: float = 0.0


_manifest_cache: dict[str, tuple[dict | None, bool | None, str | None]] = {}
_component_cache: dict[tuple[str, int, int], tuple[bool | None, str]] = {}
_lock = threading.Lock()


def build_manifest(root: Path, version: str, exclude: tuple[str, ...] = (MANIFEST_NAME, SIGNATURE_NAME)) -> dict:
    files = {}
    for dirpath, _dirs, filenames in os.walk(root):
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if rel in exclude or rel.startswith("data/"):
                continue
            files[rel] = {"sha256": sha256_file(full), "size": full.stat().st_size}
    return {"format": FORMAT, "version": version, "created": time.time(), "files": files}


def manifest_bytes(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, ensure_ascii=False, indent=1).encode("utf-8")


def load_manifest(root: Path | None = None) -> tuple[dict | None, bool | None, str | None]:
    """Return (manifest, signature_valid, key_id). signature_valid is None when no .sig exists."""
    root = Path(root) if root else app_paths.install_dir()
    key = str(root)
    with _lock:
        if key in _manifest_cache:
            return _manifest_cache[key]
    path = root / MANIFEST_NAME
    result: tuple[dict | None, bool | None, str | None] = (None, None, None)
    if path.is_file():
        raw = path.read_bytes()
        try:
            manifest = json.loads(raw)
            if manifest.get("format") != FORMAT:
                raise ValueError("formato inválido")
        except ValueError:
            result = ({}, False, None)
        else:
            sig_path = root / SIGNATURE_NAME
            if sig_path.is_file():
                kid = crypto_utils.verify(raw, sig_path.read_bytes(), crypto_utils.trusted_public_keys(include_user=False))
                result = (manifest, kid is not None, kid)
            else:
                result = (manifest, None, None)
    with _lock:
        _manifest_cache[key] = result
    return result


def _relative(path: Path, root: Path) -> str | None:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def verify_component(path: str | Path, root: Path | None = None) -> tuple[bool | None, str]:
    """(True, msg) verified; (False, msg) modified/unlisted -> must not be used; (None, msg) no manifest (dev)."""
    root = Path(root) if root else app_paths.install_dir()
    p = Path(path)
    manifest, sig_ok, _kid = load_manifest(root)
    if manifest is None:
        return None, "sem manifesto de integridade (execução de desenvolvimento)"
    if sig_ok is False:
        return False, "manifesto de integridade inválido ou com assinatura incorreta"
    rel = _relative(p, root)
    if rel is None:
        return None, "componente externo à instalação (não verificável)"
    try:
        st = p.stat()
    except OSError as exc:
        return False, f"componente inacessível: {exc}"
    cache_key = (str(p), st.st_size, st.st_mtime_ns)
    with _lock:
        if cache_key in _component_cache:
            return _component_cache[cache_key]
    entry = manifest.get("files", {}).get(rel)
    if entry is None:
        result: tuple[bool | None, str] = (False, f"{rel} não consta no manifesto de integridade")
    elif entry.get("size") != st.st_size or entry.get("sha256") != sha256_file(p):
        result = (False, f"{rel} foi modificado desde a instalação")
    else:
        result = (True, "verificado" + (" (manifesto assinado)" if sig_ok else " (manifesto sem assinatura)"))
    with _lock:
        _component_cache[cache_key] = result
    return result


def check_installation(root: Path | None = None) -> IntegrityReport:
    root = Path(root) if root else app_paths.install_dir()
    with _lock:
        _manifest_cache.pop(str(root), None)
    manifest, sig_ok, kid = load_manifest(root)
    now = time.time()
    if manifest is None:
        return IntegrityReport(
            ok=False, manifest_present=False, signature_valid=None, signer_key_id=None,
            detail="Manifesto de integridade ausente: esta é uma execução de desenvolvimento ou a instalação "
                   "está incompleta. Os componentes não puderam ser verificados.",
            checked_at=now,
        )
    report = IntegrityReport(ok=True, manifest_present=True, signature_valid=sig_ok, signer_key_id=kid, checked_at=now)
    if sig_ok is False:
        report.ok = False
        report.detail = "O manifesto de integridade não possui assinatura válida de uma chave confiável."
        return report
    for rel, entry in sorted(manifest.get("files", {}).items()):
        full = root / rel
        if not full.is_file():
            report.missing.append(rel)
            continue
        if full.stat().st_size != entry.get("size") or sha256_file(full) != entry.get("sha256"):
            report.modified.append(rel)
        else:
            report.verified += 1
    report.ok = not report.missing and not report.modified
    if report.ok:
        report.detail = f"{report.verified} componentes verificados" + (
            "; manifesto assinado." if sig_ok else "; manifesto sem assinatura (build local)."
        )
    else:
        report.detail = f"{len(report.modified)} componente(s) modificado(s), {len(report.missing)} ausente(s)."
    return report


def clear_caches() -> None:
    with _lock:
        _manifest_cache.clear()
        _component_cache.clear()
