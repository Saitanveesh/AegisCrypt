from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from kdf import derive_password_key, generate_salt
from policy import get_profile
from util import b64d, b64e, canonical_json_bytes, sha256_hex

KEY_FILE_VERSION = 1
PRIVATE_KEY_PROFILE = "hardened"


def _public_raw(public_key: X25519PublicKey) -> bytes:
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def fingerprint_public_key(public_raw: bytes) -> str:
    return sha256_hex(public_raw)[:32]


def generate_identity(
    name: str,
    passphrase: str,
    output_dir: str | Path = "keys",
) -> tuple[Path, Path]:
    if not name.strip():
        raise ValueError("Identity name cannot be empty.")

    if not passphrase:
        raise ValueError("Private-key passphrase cannot be empty.")

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_raw = private_key.private_bytes(
        Encoding.Raw,
        PrivateFormat.Raw,
        NoEncryption(),
    )
    public_raw = _public_raw(public_key)
    fingerprint = fingerprint_public_key(public_raw)

    safe_name = "".join(
        c if c.isalnum() or c in {"-", "_"} else "_"
        for c in name.strip()
    )

    public_path = output_dir / f"{safe_name}.aegis-public.json"
    private_path = output_dir / f"{safe_name}.aegis-private.json"

    if public_path.exists() or private_path.exists():
        raise FileExistsError(
            "Identity with that name already exists in the output folder."
        )

    public_doc = {
        "format": "AEGIS-PUBLIC-KEY",
        "version": KEY_FILE_VERSION,
        "algorithm": "X25519",
        "name": name.strip(),
        "fingerprint": fingerprint,
        "public_key": b64e(public_raw),
    }

    profile = get_profile(PRIVATE_KEY_PROFILE)
    salt = generate_salt()
    kek = derive_password_key(passphrase, salt, profile)
    nonce = os.urandom(12)

    aad_doc = {
        "format": "AEGIS-PRIVATE-KEY",
        "version": KEY_FILE_VERSION,
        "algorithm": "X25519",
        "name": name.strip(),
        "fingerprint": fingerprint,
        "kdf_profile": PRIVATE_KEY_PROFILE,
    }

    encrypted_private = AESGCM(kek).encrypt(
        nonce,
        private_raw,
        canonical_json_bytes(aad_doc),
    )

    private_doc = {
        **aad_doc,
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "encrypted_private_key": b64e(encrypted_private),
    }

    public_path.write_text(
        json.dumps(public_doc, indent=2),
        encoding="utf-8",
    )
    private_path.write_text(
        json.dumps(private_doc, indent=2),
        encoding="utf-8",
    )

    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass

    return public_path, private_path


def load_public_identity(path: str | Path) -> tuple[str, X25519PublicKey]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))

    if doc.get("format") != "AEGIS-PUBLIC-KEY":
        raise ValueError("Not an AegisCrypt public-key file.")

    if doc.get("algorithm") != "X25519":
        raise ValueError("Unsupported public-key algorithm.")

    public_raw = b64d(doc["public_key"])
    fingerprint = fingerprint_public_key(public_raw)

    if fingerprint != doc.get("fingerprint"):
        raise ValueError("Public-key fingerprint mismatch.")

    return fingerprint, X25519PublicKey.from_public_bytes(public_raw)


def load_private_identity(
    path: str | Path,
    passphrase: str,
) -> tuple[str, X25519PrivateKey]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))

    if doc.get("format") != "AEGIS-PRIVATE-KEY":
        raise ValueError("Not an AegisCrypt private-key file.")

    if doc.get("algorithm") != "X25519":
        raise ValueError("Unsupported private-key algorithm.")

    profile = get_profile(doc["kdf_profile"])
    salt = b64d(doc["salt"])
    nonce = b64d(doc["nonce"])
    encrypted_private = b64d(doc["encrypted_private_key"])

    aad_doc = {
        "format": doc["format"],
        "version": doc["version"],
        "algorithm": doc["algorithm"],
        "name": doc["name"],
        "fingerprint": doc["fingerprint"],
        "kdf_profile": doc["kdf_profile"],
    }

    kek = derive_password_key(passphrase, salt, profile)

    try:
        private_raw = AESGCM(kek).decrypt(
            nonce,
            encrypted_private,
            canonical_json_bytes(aad_doc),
        )
    except Exception as exc:
        raise ValueError(
            "Could not unlock private key: wrong passphrase or modified key file."
        ) from exc

    private_key = X25519PrivateKey.from_private_bytes(private_raw)
    actual_fp = fingerprint_public_key(_public_raw(private_key.public_key()))

    if actual_fp != doc["fingerprint"]:
        raise ValueError("Private-key fingerprint mismatch.")

    return actual_fp, private_key
