from __future__ import annotations

import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from container_format import build_prefix, build_signature_trailer
from envelope import wrap_key_for_recipients, wrap_key_with_password
from signatures import create_signature_document, unsigned_signature_document
from util import b64d, b64e, canonical_json_bytes
from version import __version__

CHUNK_SIZE = 1024 * 1024


def _metadata_bytes(source: Path) -> bytes:
    meta = {
        "original_name": source.name,
        "original_size": source.stat().st_size,
    }
    encoded = canonical_json_bytes(meta)
    return struct.pack(">I", len(encoded)) + encoded


def _encrypt_stream(
    source: Path,
    destination: Path,
    data_key: bytes,
    header: dict,
    *,
    signer_identity_path: str | Path | None = None,
    signer_passphrase: str | None = None,
) -> Path:
    if bool(signer_identity_path) != bool(signer_passphrase):
        raise ValueError(
            "Signing requires both a private identity file and its passphrase."
        )

    header_bytes = canonical_json_bytes(header)
    prefix = build_prefix(header_bytes)
    aad = prefix + header_bytes
    payload_nonce = b64d(header["payload"]["nonce"])

    encryptor = Cipher(
        algorithms.AES(data_key),
        modes.GCM(payload_nonce),
    ).encryptor()
    encryptor.authenticate_additional_data(aad)

    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.exists():
        raise FileExistsError(
            f"Output already exists: {destination}. "
            "AegisCrypt will not overwrite it automatically."
        )

    temp_path = destination.with_name(destination.name + ".tmp")

    try:
        with source.open("rb") as src, temp_path.open("xb") as out:
            out.write(prefix)
            out.write(header_bytes)
            out.write(encryptor.update(_metadata_bytes(source)))

            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                out.write(encryptor.update(chunk))

            out.write(encryptor.finalize())
            out.write(encryptor.tag)
            out.flush()
            os.fsync(out.fileno())

        signed_region_end = temp_path.stat().st_size

        if signer_identity_path:
            signature_doc = create_signature_document(
                temp_path,
                signed_region_end,
                signer_identity_path,
                signer_passphrase or "",
            )
        else:
            signature_doc = unsigned_signature_document()

        with temp_path.open("ab") as out:
            out.write(build_signature_trailer(signature_doc))
            out.flush()
            os.fsync(out.fileno())

        os.replace(temp_path, destination)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise

    return destination


def _base_header(mode: str, payload_nonce: bytes, key_management: dict) -> dict:
    return {
        "format": "AEGIS-CAPSULE",
        "created_with": __version__,
        "mode": mode,
        "payload": {
            "algorithm": "AES-256-GCM",
            "nonce": b64e(payload_nonce),
        },
        "key_management": key_management,
        "metadata": "encrypted",
        "sender_authentication": "none",
    }


def encrypt_password_file(
    input_path: str | Path,
    password: str,
    profile_name: str = "personal",
    output_path: str | Path | None = None,
    *,
    signer_identity_path: str | Path | None = None,
    signer_passphrase: str | None = None,
) -> Path:
    source = Path(input_path)

    if not source.is_file():
        raise FileNotFoundError(f"Input file not found: {source}")

    destination = (
        Path(output_path)
        if output_path is not None
        else source.with_name(source.name + ".aegis")
    )

    data_key = os.urandom(32)
    payload_nonce = os.urandom(12)
    header = _base_header(
        "password",
        payload_nonce,
        wrap_key_with_password(data_key, password, profile_name),
    )
    header["sender_authentication"] = (
        "ed25519" if signer_identity_path else "none"
    )

    return _encrypt_stream(
        source,
        destination,
        data_key,
        header,
        signer_identity_path=signer_identity_path,
        signer_passphrase=signer_passphrase,
    )


def encrypt_recipient_file(
    input_path: str | Path,
    public_key_paths: list[str],
    output_path: str | Path | None = None,
    *,
    signer_identity_path: str | Path | None = None,
    signer_passphrase: str | None = None,
) -> Path:
    source = Path(input_path)

    if not source.is_file():
        raise FileNotFoundError(f"Input file not found: {source}")

    destination = (
        Path(output_path)
        if output_path is not None
        else source.with_name(source.name + ".aegis")
    )

    data_key = os.urandom(32)
    payload_nonce = os.urandom(12)
    header = _base_header(
        "recipient",
        payload_nonce,
        wrap_key_for_recipients(data_key, public_key_paths),
    )
    header["sender_authentication"] = (
        "ed25519" if signer_identity_path else "none"
    )

    return _encrypt_stream(
        source,
        destination,
        data_key,
        header,
        signer_identity_path=signer_identity_path,
        signer_passphrase=signer_passphrase,
    )
