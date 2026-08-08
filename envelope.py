from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from kdf import derive_password_key, generate_salt
from keys import load_public_identity
from policy import get_profile
from util import b64d, b64e

WRAP_CONTEXT = b"AEGIS9-X25519-WRAP"


def wrap_key_with_password(
    data_key: bytes,
    password: str,
    profile_name: str,
) -> dict:
    profile = get_profile(profile_name)
    salt = generate_salt()
    kek = derive_password_key(password, salt, profile)
    nonce = os.urandom(12)
    aad = f"AEGIS9-PASSWORD-WRAP:{profile.name}".encode("utf-8")

    wrapped = AESGCM(kek).encrypt(nonce, data_key, aad)

    return {
        "type": "password",
        "kdf": "Argon2id",
        "profile": profile.name,
        "salt": b64e(salt),
        "wrap_nonce": b64e(nonce),
        "wrapped_key": b64e(wrapped),
    }


def unwrap_key_with_password(
    key_management: dict,
    password: str,
) -> bytes:
    profile = get_profile(key_management["profile"])
    salt = b64d(key_management["salt"])
    nonce = b64d(key_management["wrap_nonce"])
    wrapped = b64d(key_management["wrapped_key"])
    kek = derive_password_key(password, salt, profile)
    aad = f"AEGIS9-PASSWORD-WRAP:{profile.name}".encode("utf-8")

    try:
        return AESGCM(kek).decrypt(nonce, wrapped, aad)
    except Exception as exc:
        raise ValueError(
            "Wrong password or modified password-wrapped key."
        ) from exc


def _derive_x25519_wrap_key(
    shared_secret: bytes,
    fingerprint: str,
) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=WRAP_CONTEXT + b":" + fingerprint.encode("ascii"),
    ).derive(shared_secret)


def wrap_key_for_recipients(
    data_key: bytes,
    public_key_paths: list[str],
) -> dict:
    if not public_key_paths:
        raise ValueError("At least one recipient public key is required.")

    recipients = []
    seen: set[str] = set()

    for path in public_key_paths:
        fingerprint, recipient_public = load_public_identity(path)

        if fingerprint in seen:
            continue
        seen.add(fingerprint)

        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public_raw = ephemeral_private.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )

        shared_secret = ephemeral_private.exchange(recipient_public)
        wrap_key = _derive_x25519_wrap_key(
            shared_secret,
            fingerprint,
        )
        nonce = os.urandom(12)
        aad = f"AEGIS9-RECIPIENT:{fingerprint}".encode("ascii")
        wrapped = AESGCM(wrap_key).encrypt(
            nonce,
            data_key,
            aad,
        )

        recipients.append(
            {
                "fingerprint": fingerprint,
                "ephemeral_public": b64e(ephemeral_public_raw),
                "wrap_nonce": b64e(nonce),
                "wrapped_key": b64e(wrapped),
            }
        )

    return {
        "type": "x25519-multi-recipient",
        "kdf": "HKDF-SHA256",
        "recipients": recipients,
    }


def unwrap_key_for_identity(
    key_management: dict,
    fingerprint: str,
    private_key,
) -> bytes:
    stanza = next(
        (
            item
            for item in key_management.get("recipients", [])
            if item.get("fingerprint") == fingerprint
        ),
        None,
    )

    if stanza is None:
        raise ValueError(
            "This identity is not an authorized recipient for the capsule."
        )

    ephemeral_public = X25519PublicKey.from_public_bytes(
        b64d(stanza["ephemeral_public"])
    )
    shared_secret = private_key.exchange(ephemeral_public)
    wrap_key = _derive_x25519_wrap_key(
        shared_secret,
        fingerprint,
    )

    nonce = b64d(stanza["wrap_nonce"])
    wrapped = b64d(stanza["wrapped_key"])
    aad = f"AEGIS9-RECIPIENT:{fingerprint}".encode("ascii")

    try:
        return AESGCM(wrap_key).decrypt(
            nonce,
            wrapped,
            aad,
        )
    except Exception as exc:
        raise ValueError(
            "Recipient key unwrap failed: wrong identity or modified capsule."
        ) from exc
