from __future__ import annotations

import json
from pathlib import Path

from container_format import CONTAINER_VERSION, read_header
from decryptor import authenticate_payload, recover_data_key
from util import sha256_file


def inspect_file(input_path: str | Path) -> dict:
    source = Path(input_path)

    if not source.is_file():
        raise FileNotFoundError(f"AegisCrypt file not found: {source}")

    _, _, header, _ = read_header(source)
    km = header["key_management"]

    recipients = []

    if header["mode"] == "recipient":
        recipients = [
            item["fingerprint"]
            for item in km.get("recipients", [])
        ]

    return {
        "container": "AEGIS",
        "container_version": CONTAINER_VERSION,
        "mode": header["mode"],
        "payload_algorithm": header["payload"]["algorithm"],
        "metadata": header.get("metadata"),
        "password_profile": (
            km.get("profile")
            if header["mode"] == "password"
            else None
        ),
        "recipient_count": len(recipients),
        "recipient_fingerprints": recipients,
        "capsule_size_bytes": source.stat().st_size,
        "capsule_sha256": sha256_file(source),
        "verification_status": "NOT_VERIFIED",
    }


def verify_file(
    input_path: str | Path,
    *,
    password: str | None = None,
    identity_path: str | Path | None = None,
    identity_passphrase: str | None = None,
) -> dict:
    source = Path(input_path)

    prefix, header_bytes, header, payload_offset = read_header(source)
    data_key = recover_data_key(
        header,
        password,
        identity_path,
        identity_passphrase,
    )

    authenticate_payload(
        source,
        data_key,
        prefix,
        header_bytes,
        header,
        payload_offset,
    )

    report = inspect_file(source)
    report["verification_status"] = "VERIFIED"
    report["authenticated_header"] = True
    report["authenticated_payload"] = True
    return report


def save_security_receipt(
    input_path: str | Path,
    *,
    password: str | None = None,
    identity_path: str | Path | None = None,
    identity_passphrase: str | None = None,
    receipt_path: str | Path | None = None,
) -> Path:
    source = Path(input_path)
    report = verify_file(
        source,
        password=password,
        identity_path=identity_path,
        identity_passphrase=identity_passphrase,
    )

    destination = (
        Path(receipt_path)
        if receipt_path is not None
        else source.with_name(source.name + ".receipt.json")
    )

    if destination.exists():
        raise FileExistsError(
            f"Receipt already exists: {destination}."
        )

    destination.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
    return destination
