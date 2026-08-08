from __future__ import annotations

import json
import struct
from pathlib import Path

from util import canonical_json_bytes

MAGIC = b"AEGIS"
CONTAINER_VERSION = 5
SUPPORTED_CONTAINER_VERSIONS = {4, 5}
PREFIX_STRUCT = struct.Struct(">5sBI")
PREFIX_SIZE = PREFIX_STRUCT.size
GCM_TAG_SIZE = 16
MAX_HEADER_SIZE = 1024 * 1024

SIGNATURE_TRAILER_MAGIC = b"ASIG"
SIGNATURE_TAIL_STRUCT = struct.Struct(">I4s")
SIGNATURE_TAIL_SIZE = SIGNATURE_TAIL_STRUCT.size
MAX_SIGNATURE_TRAILER_SIZE = 256 * 1024


def build_prefix(header_bytes: bytes) -> bytes:
    if not header_bytes or len(header_bytes) > MAX_HEADER_SIZE:
        raise ValueError("AegisCrypt header size is invalid.")

    return PREFIX_STRUCT.pack(
        MAGIC,
        CONTAINER_VERSION,
        len(header_bytes),
    )


def parse_prefix(prefix: bytes) -> tuple[int, int]:
    if len(prefix) != PREFIX_SIZE:
        raise ValueError("Incomplete AegisCrypt prefix.")

    magic, version, header_len = PREFIX_STRUCT.unpack(prefix)

    if magic != MAGIC:
        raise ValueError("Not an AegisCrypt file.")

    if version not in SUPPORTED_CONTAINER_VERSIONS:
        raise ValueError(
            f"Unsupported AegisCrypt container version: {version}."
        )

    if header_len <= 0 or header_len > MAX_HEADER_SIZE:
        raise ValueError("Invalid AegisCrypt header length.")

    return version, header_len


def container_version(prefix: bytes) -> int:
    version, _ = parse_prefix(prefix)
    return version


def read_header(path: str | Path) -> tuple[bytes, bytes, dict, int]:
    source = Path(path)

    with source.open("rb") as f:
        prefix = f.read(PREFIX_SIZE)
        _, header_len = parse_prefix(prefix)
        header_bytes = f.read(header_len)

        if len(header_bytes) != header_len:
            raise ValueError("Incomplete AegisCrypt header.")

    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Invalid AegisCrypt header JSON.") from exc

    if canonical_json_bytes(header) != header_bytes:
        raise ValueError("AegisCrypt header is not in canonical form.")

    return prefix, header_bytes, header, PREFIX_SIZE + header_len


def build_signature_trailer(document: dict) -> bytes:
    encoded = canonical_json_bytes(document)

    if not encoded or len(encoded) > MAX_SIGNATURE_TRAILER_SIZE:
        raise ValueError("Signature trailer size is invalid.")

    return encoded + SIGNATURE_TAIL_STRUCT.pack(
        len(encoded),
        SIGNATURE_TRAILER_MAGIC,
    )


def read_signature_trailer(
    path: str | Path,
    *,
    prefix: bytes | None = None,
) -> tuple[dict | None, int]:
    source = Path(path)
    size = source.stat().st_size

    if prefix is None:
        with source.open("rb") as f:
            prefix = f.read(PREFIX_SIZE)

    version = container_version(prefix)

    if version == 4:
        return None, size

    if size < PREFIX_SIZE + SIGNATURE_TAIL_SIZE:
        raise ValueError("Incomplete AegisCrypt signature trailer.")

    with source.open("rb") as f:
        f.seek(size - SIGNATURE_TAIL_SIZE)
        tail = f.read(SIGNATURE_TAIL_SIZE)
        trailer_len, magic = SIGNATURE_TAIL_STRUCT.unpack(tail)

        if magic != SIGNATURE_TRAILER_MAGIC:
            raise ValueError("Missing AegisCrypt signature trailer.")

        if trailer_len <= 0 or trailer_len > MAX_SIGNATURE_TRAILER_SIZE:
            raise ValueError("Invalid AegisCrypt signature trailer length.")

        trailer_start = size - SIGNATURE_TAIL_SIZE - trailer_len

        if trailer_start <= PREFIX_SIZE:
            raise ValueError("Invalid AegisCrypt signature trailer position.")

        f.seek(trailer_start)
        trailer_bytes = f.read(trailer_len)

    try:
        document = json.loads(trailer_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Invalid AegisCrypt signature trailer JSON.") from exc

    if canonical_json_bytes(document) != trailer_bytes:
        raise ValueError("AegisCrypt signature trailer is not canonical.")

    return document, trailer_start


def encrypted_region_end(
    path: str | Path,
    *,
    prefix: bytes | None = None,
) -> int:
    _, trailer_start = read_signature_trailer(path, prefix=prefix)
    return trailer_start
