from __future__ import annotations

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keys import fingerprint_public_key, load_private_identity_bundle
from trust_store import trust_status_for_signer
from util import b64d, b64e, sha256_file_region

SIGNATURE_FORMAT = "AEGIS-SIGNATURE"
SIGNATURE_VERSION = 1
SIGNATURE_CONTEXT = b"AEGISCRYPT-V7-CAPSULE-SIGNATURE\x00"


def unsigned_signature_document() -> dict:
    return {
        "format": SIGNATURE_FORMAT,
        "version": SIGNATURE_VERSION,
        "signed": False,
    }


def create_signature_document(
    path: str | Path,
    signed_region_end: int,
    identity_path: str | Path,
    passphrase: str,
) -> dict:
    bundle = load_private_identity_bundle(identity_path, passphrase)
    signing_private = bundle.get("signing_private_key")

    if signing_private is None:
        raise ValueError(
            "This legacy identity cannot sign capsules. Generate a new AegisCrypt 7 identity."
        )

    signing_public_raw = signing_private.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )
    signing_fp = fingerprint_public_key(signing_public_raw)
    digest_hex = sha256_file_region(path, signed_region_end)
    digest_bytes = bytes.fromhex(digest_hex)
    signature = signing_private.sign(SIGNATURE_CONTEXT + digest_bytes)

    return {
        "format": SIGNATURE_FORMAT,
        "version": SIGNATURE_VERSION,
        "signed": True,
        "algorithm": "Ed25519",
        "digest_algorithm": "SHA-256",
        "capsule_digest": digest_hex,
        "signer_name": bundle["name"],
        "signing_fingerprint": signing_fp,
        "signing_public_key": b64e(signing_public_raw),
        "signature": b64e(signature),
    }


def enforce_signature_policy(header: dict, document: dict | None) -> None:
    expected = header.get("sender_authentication", "none")
    if expected not in {"none", "ed25519"}:
        raise ValueError("Unsupported sender-authentication policy.")

    signed = bool(document and document.get("signed"))

    if expected == "ed25519" and not signed:
        raise ValueError(
            "Capsule requires an Ed25519 sender signature, but none is present."
        )

    if expected == "none" and signed:
        raise ValueError(
            "Capsule signature trailer conflicts with the authenticated header policy."
        )


def verify_signature_document(
    path: str | Path,
    document: dict | None,
    signed_region_end: int,
    *,
    trust_store_path: str | Path | None = None,
) -> dict:
    if document is None:
        return {
            "signature_status": "UNSIGNED",
            "signed": False,
            "signer_name": None,
            "signing_fingerprint": None,
            "trust_status": "not-applicable",
        }

    if document.get("format") != SIGNATURE_FORMAT or document.get("version") != 1:
        raise ValueError("Unsupported AegisCrypt signature trailer.")

    if document.get("signed") is False:
        return {
            "signature_status": "UNSIGNED",
            "signed": False,
            "signer_name": None,
            "signing_fingerprint": None,
            "trust_status": "not-applicable",
        }

    if document.get("algorithm") != "Ed25519":
        raise ValueError("Unsupported capsule signature algorithm.")
    if document.get("digest_algorithm") != "SHA-256":
        raise ValueError("Unsupported capsule signature digest algorithm.")

    public_raw = b64d(document["signing_public_key"])
    signing_fp = fingerprint_public_key(public_raw)

    if signing_fp != document.get("signing_fingerprint"):
        raise ValueError("Capsule signer fingerprint mismatch.")

    actual_digest = sha256_file_region(path, signed_region_end)
    if actual_digest != document.get("capsule_digest"):
        raise ValueError("Capsule signature digest mismatch.")

    public_key = Ed25519PublicKey.from_public_bytes(public_raw)

    try:
        public_key.verify(
            b64d(document["signature"]),
            SIGNATURE_CONTEXT + bytes.fromhex(actual_digest),
        )
    except InvalidSignature as exc:
        raise ValueError("Capsule sender signature is invalid.") from exc

    trust_status = trust_status_for_signer(
        signing_fp,
        store_path=trust_store_path,
    )

    return {
        "signature_status": "VALID",
        "signed": True,
        "signer_name": document.get("signer_name"),
        "signing_fingerprint": signing_fp,
        "trust_status": trust_status,
    }
