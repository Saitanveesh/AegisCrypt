from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
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
from util import atomic_write_text, b64d, b64e, canonical_json_bytes, sha256_hex

KEY_FILE_VERSION = 2
PRIVATE_KEY_PROFILE = "hardened"


def _raw_public(public_key) -> bytes:
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _raw_private(private_key) -> bytes:
    return private_key.private_bytes(
        Encoding.Raw,
        PrivateFormat.Raw,
        NoEncryption(),
    )


def fingerprint_public_key(public_raw: bytes) -> str:
    return sha256_hex(public_raw)[:32]


def generate_identity(
    name: str,
    passphrase: str,
    output_dir: str | Path = "keys",
) -> tuple[Path, Path]:
    clean_name = name.strip()
    if not clean_name:
        raise ValueError("Identity name cannot be empty.")

    if not passphrase:
        raise ValueError("Private-key passphrase cannot be empty.")

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    encryption_private = X25519PrivateKey.generate()
    encryption_public = encryption_private.public_key()
    signing_private = Ed25519PrivateKey.generate()
    signing_public = signing_private.public_key()

    encryption_public_raw = _raw_public(encryption_public)
    signing_public_raw = _raw_public(signing_public)
    encryption_fp = fingerprint_public_key(encryption_public_raw)
    signing_fp = fingerprint_public_key(signing_public_raw)

    safe_name = "".join(
        c if c.isalnum() or c in {"-", "_"} else "_"
        for c in clean_name
    )

    public_path = output_dir / f"{safe_name}.aegis-public.json"
    private_path = output_dir / f"{safe_name}.aegis-private.json"

    if public_path.exists() or private_path.exists():
        raise FileExistsError(
            "Identity with that name already exists in the output folder."
        )

    public_doc = {
        "format": "AEGIS-IDENTITY-PUBLIC",
        "version": KEY_FILE_VERSION,
        "name": clean_name,
        "encryption": {
            "algorithm": "X25519",
            "fingerprint": encryption_fp,
            "public_key": b64e(encryption_public_raw),
        },
        "signing": {
            "algorithm": "Ed25519",
            "fingerprint": signing_fp,
            "public_key": b64e(signing_public_raw),
        },
    }

    profile = get_profile(PRIVATE_KEY_PROFILE)
    salt = generate_salt()
    kek = derive_password_key(passphrase, salt, profile)
    nonce = os.urandom(12)

    aad_doc = {
        "format": "AEGIS-IDENTITY-PRIVATE",
        "version": KEY_FILE_VERSION,
        "name": clean_name,
        "encryption_fingerprint": encryption_fp,
        "signing_fingerprint": signing_fp,
        "kdf_profile": PRIVATE_KEY_PROFILE,
    }

    secret_doc = {
        "x25519_private": b64e(_raw_private(encryption_private)),
        "ed25519_private": b64e(_raw_private(signing_private)),
    }

    encrypted_private = AESGCM(kek).encrypt(
        nonce,
        canonical_json_bytes(secret_doc),
        canonical_json_bytes(aad_doc),
    )

    private_doc = {
        **aad_doc,
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "encrypted_private_key": b64e(encrypted_private),
    }

    atomic_write_text(
        public_path,
        json.dumps(public_doc, indent=2) + "\n",
    )
    atomic_write_text(
        private_path,
        json.dumps(private_doc, indent=2) + "\n",
    )

    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass

    return public_path, private_path


def _load_public_v1(doc: dict) -> dict:
    if doc.get("algorithm") != "X25519":
        raise ValueError("Unsupported legacy public-key algorithm.")

    public_raw = b64d(doc["public_key"])
    fingerprint = fingerprint_public_key(public_raw)

    if fingerprint != doc.get("fingerprint"):
        raise ValueError("Public-key fingerprint mismatch.")

    return {
        "version": 1,
        "name": doc.get("name", "Legacy identity"),
        "encryption_fingerprint": fingerprint,
        "encryption_public_key": X25519PublicKey.from_public_bytes(public_raw),
        "signing_fingerprint": None,
        "signing_public_key": None,
    }


def load_public_identity_bundle(path: str | Path) -> dict:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))

    if doc.get("format") == "AEGIS-PUBLIC-KEY":
        return _load_public_v1(doc)

    if doc.get("format") != "AEGIS-IDENTITY-PUBLIC" or doc.get("version") != 2:
        raise ValueError("Not a supported AegisCrypt public identity file.")

    encryption = doc.get("encryption", {})
    signing = doc.get("signing", {})

    if encryption.get("algorithm") != "X25519":
        raise ValueError("Unsupported encryption identity algorithm.")
    if signing.get("algorithm") != "Ed25519":
        raise ValueError("Unsupported signing identity algorithm.")

    encryption_raw = b64d(encryption["public_key"])
    signing_raw = b64d(signing["public_key"])
    encryption_fp = fingerprint_public_key(encryption_raw)
    signing_fp = fingerprint_public_key(signing_raw)

    if encryption_fp != encryption.get("fingerprint"):
        raise ValueError("Encryption-key fingerprint mismatch.")
    if signing_fp != signing.get("fingerprint"):
        raise ValueError("Signing-key fingerprint mismatch.")

    return {
        "version": 2,
        "name": doc.get("name", "Unnamed identity"),
        "encryption_fingerprint": encryption_fp,
        "encryption_public_key": X25519PublicKey.from_public_bytes(encryption_raw),
        "signing_fingerprint": signing_fp,
        "signing_public_key": Ed25519PublicKey.from_public_bytes(signing_raw),
    }


def load_public_identity(path: str | Path) -> tuple[str, X25519PublicKey]:
    bundle = load_public_identity_bundle(path)
    return bundle["encryption_fingerprint"], bundle["encryption_public_key"]


def _load_private_v1(doc: dict, passphrase: str) -> dict:
    if doc.get("algorithm") != "X25519":
        raise ValueError("Unsupported legacy private-key algorithm.")

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

    encryption_private = X25519PrivateKey.from_private_bytes(private_raw)
    encryption_fp = fingerprint_public_key(_raw_public(encryption_private.public_key()))

    if encryption_fp != doc["fingerprint"]:
        raise ValueError("Private-key fingerprint mismatch.")

    return {
        "version": 1,
        "name": doc.get("name", "Legacy identity"),
        "encryption_fingerprint": encryption_fp,
        "encryption_private_key": encryption_private,
        "signing_fingerprint": None,
        "signing_private_key": None,
    }


def load_private_identity_bundle(
    path: str | Path,
    passphrase: str,
) -> dict:
    if not passphrase:
        raise ValueError("Private-key passphrase cannot be empty.")

    doc = json.loads(Path(path).read_text(encoding="utf-8"))

    if doc.get("format") == "AEGIS-PRIVATE-KEY":
        return _load_private_v1(doc, passphrase)

    if doc.get("format") != "AEGIS-IDENTITY-PRIVATE" or doc.get("version") != 2:
        raise ValueError("Not a supported AegisCrypt private identity file.")

    profile = get_profile(doc["kdf_profile"])
    salt = b64d(doc["salt"])
    nonce = b64d(doc["nonce"])
    encrypted_private = b64d(doc["encrypted_private_key"])

    aad_doc = {
        "format": doc["format"],
        "version": doc["version"],
        "name": doc["name"],
        "encryption_fingerprint": doc["encryption_fingerprint"],
        "signing_fingerprint": doc["signing_fingerprint"],
        "kdf_profile": doc["kdf_profile"],
    }

    kek = derive_password_key(passphrase, salt, profile)

    try:
        secret_raw = AESGCM(kek).decrypt(
            nonce,
            encrypted_private,
            canonical_json_bytes(aad_doc),
        )
        secret_doc = json.loads(secret_raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError(
            "Could not unlock private identity: wrong passphrase or modified key file."
        ) from exc

    encryption_private = X25519PrivateKey.from_private_bytes(
        b64d(secret_doc["x25519_private"])
    )
    signing_private = Ed25519PrivateKey.from_private_bytes(
        b64d(secret_doc["ed25519_private"])
    )

    encryption_fp = fingerprint_public_key(_raw_public(encryption_private.public_key()))
    signing_fp = fingerprint_public_key(_raw_public(signing_private.public_key()))

    if encryption_fp != doc["encryption_fingerprint"]:
        raise ValueError("Encryption private-key fingerprint mismatch.")
    if signing_fp != doc["signing_fingerprint"]:
        raise ValueError("Signing private-key fingerprint mismatch.")

    return {
        "version": 2,
        "name": doc.get("name", "Unnamed identity"),
        "encryption_fingerprint": encryption_fp,
        "encryption_private_key": encryption_private,
        "signing_fingerprint": signing_fp,
        "signing_private_key": signing_private,
    }


def load_private_identity(
    path: str | Path,
    passphrase: str,
) -> tuple[str, X25519PrivateKey]:
    bundle = load_private_identity_bundle(path, passphrase)
    return bundle["encryption_fingerprint"], bundle["encryption_private_key"]
