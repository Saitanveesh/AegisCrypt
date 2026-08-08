from __future__ import annotations

import json
import struct
from pathlib import Path

from util import canonical_json_bytes

MAGIC = b"AEGIS"
CONTAINER_VERSION = 4
PREFIX_STRUCT = struct.Struct(">5sBI")
PREFIX_SIZE = PREFIX_STRUCT.size
GCM_TAG_SIZE = 16
MAX_HEADER_SIZE = 1024 * 1024


def build_prefix(header_bytes: bytes) -> bytes:
    if not header_bytes or len(header_bytes) > MAX_HEADER_SIZE:
        raise ValueError("AegisCrypt header size is invalid.")

    return PREFIX_STRUCT.pack(
        MAGIC,
        CONTAINER_VERSION,
        len(header_bytes),
    )


def read_header(path: str | Path) -> tuple[bytes, bytes, dict, int]:
    source = Path(path)

    with source.open("rb") as f:
        prefix = f.read(PREFIX_SIZE)

        if len(prefix) != PREFIX_SIZE:
            raise ValueError("Incomplete AegisCrypt prefix.")

        magic, version, header_len = PREFIX_STRUCT.unpack(prefix)

        if magic != MAGIC:
            raise ValueError("Not an AegisCrypt file.")

        if version != CONTAINER_VERSION:
            raise ValueError(
                f"Unsupported container version {version}; "
                f"this build reads version {CONTAINER_VERSION}."
            )

        if header_len <= 0 or header_len > MAX_HEADER_SIZE:
            raise ValueError("Invalid AegisCrypt header length.")

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
