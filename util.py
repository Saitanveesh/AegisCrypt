from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def canonical_json_bytes(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def sha256_file_region(
    path: str | Path,
    end_offset: int,
    chunk_size: int = 1024 * 1024,
) -> str:
    if end_offset < 0:
        raise ValueError("end_offset cannot be negative.")

    digest = hashlib.sha256()
    remaining = end_offset

    with Path(path).open("rb") as f:
        while remaining:
            chunk = f.read(min(chunk_size, remaining))
            if not chunk:
                raise ValueError("File ended before the requested digest region.")
            remaining -= len(chunk)
            digest.update(chunk)

    return digest.hexdigest()


def unique_path(path: str | Path) -> Path:
    candidate = Path(path)
    if not candidate.exists():
        return candidate

    parent = candidate.parent
    stem = candidate.stem
    suffix = candidate.suffix

    for i in range(2, 10000):
        next_path = parent / f"{stem}-{i}{suffix}"
        if not next_path.exists():
            return next_path

    raise RuntimeError("Could not choose a unique output path.")


def atomic_write_text(path: str | Path, text: str) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_name(destination.name + ".tmp")

    try:
        with temp.open("x", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, destination)
    except Exception:
        temp.unlink(missing_ok=True)
        raise

    return destination
