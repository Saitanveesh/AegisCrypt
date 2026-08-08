from __future__ import annotations

import json
import os
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from container_format import GCM_TAG_SIZE, encrypted_region_end, read_header
from envelope import unwrap_key_for_identity, unwrap_key_with_password
from keys import load_private_identity
from util import b64d, unique_path

CHUNK_SIZE = 1024 * 1024
MAX_METADATA_SIZE = 1024 * 1024


def recover_data_key(
    header: dict,
    password: str | None,
    identity_path: str | Path | None,
    identity_passphrase: str | None,
) -> bytes:
    mode = header.get("mode")
    km = header["key_management"]

    if mode == "password":
        if password is None:
            raise ValueError("Password is required for this capsule.")
        return unwrap_key_with_password(km, password)

    if mode == "recipient":
        if identity_path is None:
            raise ValueError(
                "A private identity file is required for this recipient capsule."
            )
        if identity_passphrase is None:
            raise ValueError("Private-key passphrase is required.")

        fingerprint, private_key = load_private_identity(
            identity_path,
            identity_passphrase,
        )
        return unwrap_key_for_identity(km, fingerprint, private_key)

    raise ValueError(f"Unsupported AegisCrypt mode: {mode}")


def _ciphertext_layout(
    source: Path,
    payload_offset: int,
    prefix: bytes,
) -> tuple[int, bytes]:
    encrypted_end = encrypted_region_end(source, prefix=prefix)

    if encrypted_end <= payload_offset + GCM_TAG_SIZE:
        raise ValueError("Incomplete encrypted payload.")

    ciphertext_len = encrypted_end - payload_offset - GCM_TAG_SIZE

    with source.open("rb") as src:
        src.seek(encrypted_end - GCM_TAG_SIZE)
        tag = src.read(GCM_TAG_SIZE)

    if len(tag) != GCM_TAG_SIZE:
        raise ValueError("Incomplete authentication tag.")

    return ciphertext_len, tag


def authenticate_payload(
    source: Path,
    data_key: bytes,
    prefix: bytes,
    header_bytes: bytes,
    header: dict,
    payload_offset: int,
) -> None:
    ciphertext_len, tag = _ciphertext_layout(source, payload_offset, prefix)

    decryptor = Cipher(
        algorithms.AES(data_key),
        modes.GCM(b64d(header["payload"]["nonce"]), tag),
    ).decryptor()
    decryptor.authenticate_additional_data(prefix + header_bytes)

    remaining = ciphertext_len

    with source.open("rb") as src:
        src.seek(payload_offset)

        while remaining:
            chunk = src.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                raise ValueError("Unexpected end of encrypted payload.")
            remaining -= len(chunk)
            decryptor.update(chunk)

    try:
        decryptor.finalize()
    except InvalidTag as exc:
        raise ValueError(
            "Authentication failed: wrong credential or modified capsule."
        ) from exc


def _safe_original_name(name: str) -> str:
    if not isinstance(name, str) or not name:
        return "decrypted-file"
    safe = Path(name).name
    if safe in {"", ".", ".."}:
        return "decrypted-file"
    return safe


def _decrypt_verified_to_output(
    source: Path,
    data_key: bytes,
    prefix: bytes,
    header_bytes: bytes,
    header: dict,
    payload_offset: int,
    output_path: str | Path | None,
) -> Path:
    ciphertext_len, tag = _ciphertext_layout(source, payload_offset, prefix)

    decryptor = Cipher(
        algorithms.AES(data_key),
        modes.GCM(b64d(header["payload"]["nonce"]), tag),
    ).decryptor()
    decryptor.authenticate_additional_data(prefix + header_bytes)

    remaining = ciphertext_len
    pending = bytearray()
    metadata = None
    destination = None
    temp_output = None
    out = None

    try:
        with source.open("rb") as src:
            src.seek(payload_offset)

            while remaining:
                chunk = src.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise ValueError("Unexpected end of encrypted payload.")

                remaining -= len(chunk)
                plain = decryptor.update(chunk)

                if metadata is None:
                    pending.extend(plain)

                    if len(pending) >= 4:
                        metadata_len = struct.unpack(">I", pending[:4])[0]
                        if metadata_len <= 0 or metadata_len > MAX_METADATA_SIZE:
                            raise ValueError("Invalid encrypted metadata length.")

                        total_meta = 4 + metadata_len
                        if len(pending) >= total_meta:
                            metadata = json.loads(
                                bytes(pending[4:total_meta]).decode("utf-8")
                            )

                            if output_path is not None:
                                destination = Path(output_path)
                            else:
                                original_name = _safe_original_name(
                                    metadata.get("original_name", "")
                                )
                                destination = unique_path(
                                    source.with_name(original_name + ".decrypted")
                                )

                            destination.parent.mkdir(parents=True, exist_ok=True)
                            if destination.exists():
                                raise FileExistsError(
                                    f"Output already exists: {destination}."
                                )

                            temp_output = destination.with_name(
                                destination.name + ".tmp"
                            )
                            out = temp_output.open("xb")
                            out.write(pending[total_meta:])
                            pending.clear()
                else:
                    out.write(plain)

            final_plain = decryptor.finalize()

            if metadata is None:
                pending.extend(final_plain)
                if len(pending) < 4:
                    raise ValueError("Encrypted metadata is incomplete.")

                metadata_len = struct.unpack(">I", pending[:4])[0]
                total_meta = 4 + metadata_len

                if (
                    metadata_len <= 0
                    or metadata_len > MAX_METADATA_SIZE
                    or len(pending) < total_meta
                ):
                    raise ValueError("Encrypted metadata is incomplete.")

                metadata = json.loads(bytes(pending[4:total_meta]).decode("utf-8"))

                if output_path is not None:
                    destination = Path(output_path)
                else:
                    original_name = _safe_original_name(
                        metadata.get("original_name", "")
                    )
                    destination = unique_path(
                        source.with_name(original_name + ".decrypted")
                    )

                destination.parent.mkdir(parents=True, exist_ok=True)
                temp_output = destination.with_name(destination.name + ".tmp")
                out = temp_output.open("xb")
                out.write(pending[total_meta:])
            else:
                out.write(final_plain)

            out.flush()
            os.fsync(out.fileno())
            out.close()
            out = None

        os.replace(temp_output, destination)
        return destination
    except Exception:
        if out is not None:
            out.close()
        if temp_output is not None:
            Path(temp_output).unlink(missing_ok=True)
        raise


def decrypt_file(
    input_path: str | Path,
    *,
    password: str | None = None,
    identity_path: str | Path | None = None,
    identity_passphrase: str | None = None,
    output_path: str | Path | None = None,
) -> Path:
    source = Path(input_path)

    if not source.is_file():
        raise FileNotFoundError(f"AegisCrypt file not found: {source}")

    prefix, header_bytes, header, payload_offset = read_header(source)
    data_key = recover_data_key(
        header,
        password,
        identity_path,
        identity_passphrase,
    )

    # Authenticate first. Plaintext is not written until this pass succeeds.
    authenticate_payload(
        source,
        data_key,
        prefix,
        header_bytes,
        header,
        payload_offset,
    )

    return _decrypt_verified_to_output(
        source,
        data_key,
        prefix,
        header_bytes,
        header,
        payload_offset,
        output_path,
    )
