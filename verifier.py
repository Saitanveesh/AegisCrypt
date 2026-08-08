from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from container_format import (
    container_version,
    read_header,
    read_signature_trailer,
)
from decryptor import authenticate_payload, recover_data_key
from signatures import verify_signature_document
from util import atomic_write_text, sha256_file
from version import __version__


def inspect_file(input_path: str | Path) -> dict:
    source = Path(input_path)

    if not source.is_file():
        raise FileNotFoundError(f"AegisCrypt file not found: {source}")

    prefix, _, header, _ = read_header(source)
    signature_doc, _ = read_signature_trailer(source, prefix=prefix)
    km = header["key_management"]

    recipients = []
    if header["mode"] == "recipient":
        recipients = [
            item["fingerprint"]
            for item in km.get("recipients", [])
        ]

    signed = bool(signature_doc and signature_doc.get("signed"))

    return {
        "container": "AEGIS",
        "container_version": container_version(prefix),
        "created_with": header.get("created_with"),
        "mode": header["mode"],
        "payload_algorithm": header["payload"]["algorithm"],
        "metadata": header.get("metadata"),
        "password_profile": (
            km.get("profile") if header["mode"] == "password" else None
        ),
        "recipient_count": len(recipients),
        "recipient_fingerprints": recipients,
        "signed": signed,
        "signer_name": signature_doc.get("signer_name") if signed else None,
        "signing_fingerprint": (
            signature_doc.get("signing_fingerprint") if signed else None
        ),
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
    trust_store_path: str | Path | None = None,
) -> dict:
    source = Path(input_path)
    prefix, header_bytes, header, payload_offset = read_header(source)
    signature_doc, signed_region_end = read_signature_trailer(source, prefix=prefix)

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

    signature_report = verify_signature_document(
        source,
        signature_doc,
        signed_region_end,
        trust_store_path=trust_store_path,
    )

    if signature_report.get("trust_status") == "blocked":
        raise ValueError("Capsule is signed by a locally blocked identity.")

    report = inspect_file(source)
    report.update(signature_report)
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
    trust_store_path: str | Path | None = None,
) -> Path:
    source = Path(input_path)
    report = verify_file(
        source,
        password=password,
        identity_path=identity_path,
        identity_passphrase=identity_passphrase,
        trust_store_path=trust_store_path,
    )

    report = {
        "receipt_format": "AEGIS-SECURITY-RECEIPT",
        "receipt_version": 2,
        "aegiscrypt_version": __version__,
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        **report,
    }

    destination = (
        Path(receipt_path)
        if receipt_path is not None
        else source.with_name(source.name + ".receipt.json")
    )

    if destination.exists():
        raise FileExistsError(f"Receipt already exists: {destination}.")

    atomic_write_text(destination, json.dumps(report, indent=2) + "\n")
    return destination
