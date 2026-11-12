"""Ed25519 helpers shared by offline update packages and the installation integrity manifest.

Trusted public keys are PEM files (``*.pub``) in:
  * <install>/signatures/keys/          — shipped with the application (read-only)
  * <data>/trusted_keys/                — added by the user after explicit confirmation
Key identifier = first 16 hex chars of SHA-256 over the raw 32-byte public key.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import app_paths


def generate_keypair(password: bytes | None = None) -> tuple[bytes, bytes]:
    """Return (private_pem, public_pem). Encrypt the private key when a password is given."""
    private = Ed25519PrivateKey.generate()
    encryption = (
        serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    )
    private_pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


def load_private_key(pem: bytes, password: bytes | None = None) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("A chave privada não é Ed25519")
    return key


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("A chave pública não é Ed25519")
    return key


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    return private_key.sign(data)


def user_trusted_keys_dir() -> Path:
    path = app_paths.data_dir() / "trusted_keys"
    path.mkdir(parents=True, exist_ok=True)
    return path


def trusted_public_keys(include_user: bool = True, extra_dirs: list[Path] | None = None) -> dict[str, Ed25519PublicKey]:
    dirs = [app_paths.trusted_keys_dir()]
    if include_user:
        dirs.append(user_trusted_keys_dir())
    dirs += list(extra_dirs or [])
    keys: dict[str, Ed25519PublicKey] = {}
    for directory in dirs:
        if not directory.is_dir():
            continue
        for pub in sorted(directory.glob("*.pub")):
            try:
                key = load_public_key(pub.read_bytes())
            except (ValueError, OSError):
                continue
            keys[key_id(key)] = key
    return keys


def verify(data: bytes, signature: bytes, keys: dict[str, Ed25519PublicKey] | None = None) -> str | None:
    """Return the id of the trusted key that produced ``signature`` over ``data``, or None."""
    keys = trusted_public_keys() if keys is None else keys
    for kid, key in keys.items():
        try:
            key.verify(signature, data)
            return kid
        except InvalidSignature:
            continue
    return None
