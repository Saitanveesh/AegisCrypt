from __future__ import annotations

import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from container_format import build_prefix
from envelope import wrap_key_for_recipients, wrap_key_with_password
from util import b64e, canonical_json_bytes

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
) -> Path:
    header_bytes = canonical_json_bytes(header)
    prefix = build_prefix(header_bytes)
    aad = prefix + header_bytes

    from util import b64d
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

        os.replace(temp_path, destination)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise

    return destination


def encrypt_password_file(
    input_path: str | Path,
    password: str,
    profile_name: str = "personal",
    output_path: str | Path | None = None,
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

    header = {
        "mode": "password",
        "payload": {
            "algorithm": "AES-256-GCM",
            "nonce": b64e(payload_nonce),
        },
        "key_management": wrap_key_with_password(
            data_key,
            password,
            profile_name,
        ),
        "metadata": "encrypted",
    }

    return _encrypt_stream(
        source,
        destination,
        data_key,
        header,
    )


def encrypt_recipient_file(
    input_path: str | Path,
    public_key_paths: list[str],
    output_path: str | Path | None = None,
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

    header = {
        "mode": "recipient",
        "payload": {
            "algorithm": "AES-256-GCM",
            "nonce": b64e(payload_nonce),
        },
        "key_management": wrap_key_for_recipients(
            data_key,
            public_key_paths,
        ),
        "metadata": "encrypted",
    }

    return _encrypt_stream(
        source,
        destination,
        data_key,
        header,
    )
