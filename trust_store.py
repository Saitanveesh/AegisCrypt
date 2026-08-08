from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from keys import load_public_identity_bundle
from util import atomic_write_text

TRUST_STATES = {"unverified", "trusted", "blocked"}


def app_data_dir() -> Path:
    override = os.environ.get("AEGISCRYPT_HOME")
    if override:
        return Path(override).expanduser().resolve()

    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home()))
        return base / "AegisCrypt"

    return Path.home() / ".aegiscrypt"


def default_store_path() -> Path:
    return app_data_dir() / "contacts.json"


def _load(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "contacts": {}}

    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("Could not read the AegisCrypt contact store.") from exc

    if doc.get("version") != 1 or not isinstance(doc.get("contacts"), dict):
        raise ValueError("Unsupported AegisCrypt contact store format.")

    return doc


def _save(path: Path, doc: dict) -> None:
    atomic_write_text(path, json.dumps(doc, indent=2) + "\n")


def import_contact(
    public_identity_path: str | Path,
    *,
    trust: str = "unverified",
    store_path: str | Path | None = None,
) -> dict:
    if trust not in TRUST_STATES:
        raise ValueError(f"Trust must be one of: {', '.join(sorted(TRUST_STATES))}.")

    bundle = load_public_identity_bundle(public_identity_path)
    path = Path(store_path) if store_path is not None else default_store_path()
    doc = _load(path)

    key = bundle["signing_fingerprint"] or bundle["encryption_fingerprint"]
    now = datetime.now(timezone.utc).isoformat()

    contact = {
        "name": bundle["name"],
        "encryption_fingerprint": bundle["encryption_fingerprint"],
        "signing_fingerprint": bundle["signing_fingerprint"],
        "trust": trust,
        "imported_at_utc": now,
    }

    doc["contacts"][key] = contact
    _save(path, doc)
    return contact


def list_contacts(*, store_path: str | Path | None = None) -> list[dict]:
    path = Path(store_path) if store_path is not None else default_store_path()
    doc = _load(path)
    return sorted(
        doc["contacts"].values(),
        key=lambda item: (item.get("name", "").lower(), item.get("signing_fingerprint") or ""),
    )


def set_contact_trust(
    fingerprint: str,
    trust: str,
    *,
    store_path: str | Path | None = None,
) -> dict:
    if trust not in TRUST_STATES:
        raise ValueError(f"Trust must be one of: {', '.join(sorted(TRUST_STATES))}.")

    path = Path(store_path) if store_path is not None else default_store_path()
    doc = _load(path)

    for key, contact in doc["contacts"].items():
        if fingerprint in {
            key,
            contact.get("signing_fingerprint"),
            contact.get("encryption_fingerprint"),
        }:
            contact["trust"] = trust
            _save(path, doc)
            return contact

    raise ValueError("No contact matches that fingerprint.")


def trust_status_for_signer(
    signing_fingerprint: str | None,
    *,
    store_path: str | Path | None = None,
) -> str:
    if not signing_fingerprint:
        return "not-applicable"

    path = Path(store_path) if store_path is not None else default_store_path()
    doc = _load(path)

    for key, contact in doc["contacts"].items():
        if signing_fingerprint in {key, contact.get("signing_fingerprint")}:
            return contact.get("trust", "unverified")

    return "unknown"
