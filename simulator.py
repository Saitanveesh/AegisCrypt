from __future__ import annotations

import json
import tempfile
from pathlib import Path

from container_format import (
    PREFIX_SIZE,
    build_signature_trailer,
    read_header,
    read_signature_trailer,
)
from util import b64d, b64e, canonical_json_bytes
from verifier import verify_file


def _verify(
    path: Path,
    password: str | None,
    identity_path: str | Path | None,
    identity_passphrase: str | None,
    trust_store_path: str | Path | None,
) -> bool:
    try:
        verify_file(
            path,
            password=password,
            identity_path=identity_path,
            identity_passphrase=identity_passphrase,
            trust_store_path=trust_store_path,
        )
        return True
    except Exception:
        return False


def simulate_attacks(
    input_path: str | Path,
    *,
    password: str | None = None,
    identity_path: str | Path | None = None,
    identity_passphrase: str | None = None,
    trust_store_path: str | Path | None = None,
) -> dict:
    source = Path(input_path)

    if not _verify(
        source,
        password,
        identity_path,
        identity_passphrase,
        trust_store_path,
    ):
        raise ValueError(
            "Baseline verification failed. Use the correct credential "
            "and an unmodified capsule."
        )

    original = source.read_bytes()
    prefix, header_bytes, header, payload_offset = read_header(source)
    signature_doc, signature_start = read_signature_trailer(source, prefix=prefix)
    results = []

    def run(name: str, mutated: bytes):
        with tempfile.NamedTemporaryFile(suffix=".aegis", delete=False) as f:
            temp_path = Path(f.name)
            f.write(mutated)

        try:
            accepted = _verify(
                temp_path,
                password,
                identity_path,
                identity_passphrase,
                trust_store_path,
            )
        finally:
            temp_path.unlink(missing_ok=True)

        results.append(
            {
                "attack": name,
                "observed": "ACCEPTED" if accepted else "REJECTED",
                "detected": not accepted,
            }
        )

    mutated = bytearray(original)
    mutated[5] ^= 0x01
    run("Container version modified", bytes(mutated))

    h = json.loads(header_bytes.decode("utf-8"))
    nonce = bytearray(b64d(h["payload"]["nonce"]))
    nonce[0] ^= 1
    h["payload"]["nonce"] = b64e(bytes(nonce))
    new_header = canonical_json_bytes(h)
    if len(new_header) == len(header_bytes):
        run(
            "Payload nonce modified",
            original[:PREFIX_SIZE] + new_header + original[payload_offset:],
        )

    h = json.loads(header_bytes.decode("utf-8"))
    if h["mode"] == "password":
        wrapped = bytearray(b64d(h["key_management"]["wrapped_key"]))
        wrapped[0] ^= 1
        h["key_management"]["wrapped_key"] = b64e(bytes(wrapped))
    else:
        wrapped = bytearray(
            b64d(h["key_management"]["recipients"][0]["wrapped_key"])
        )
        wrapped[0] ^= 1
        h["key_management"]["recipients"][0]["wrapped_key"] = b64e(bytes(wrapped))
    new_header = canonical_json_bytes(h)
    if len(new_header) == len(header_bytes):
        run(
            "Wrapped data key modified",
            original[:PREFIX_SIZE] + new_header + original[payload_offset:],
        )

    mutated = bytearray(original)
    if payload_offset < signature_start - 16:
        mutated[payload_offset] ^= 1
        run("Ciphertext bit flipped", bytes(mutated))

    mutated = bytearray(original)
    mutated[signature_start - 1] ^= 1
    run("Authentication tag modified", bytes(mutated))

    run("Capsule truncated", original[:-1])
    run("Extra byte appended", original + b"\x00")

    if signature_doc and signature_doc.get("signed"):
        s = dict(signature_doc)
        sig = bytearray(b64d(s["signature"]))
        sig[0] ^= 1
        s["signature"] = b64e(bytes(sig))
        run(
            "Sender signature modified",
            original[:signature_start] + build_signature_trailer(s),
        )

        s = dict(signature_doc)
        pub = bytearray(b64d(s["signing_public_key"]))
        pub[0] ^= 1
        s["signing_public_key"] = b64e(bytes(pub))
        run(
            "Signer public key modified",
            original[:signature_start] + build_signature_trailer(s),
        )

        s = dict(signature_doc)
        digest = list(s["capsule_digest"])
        digest[0] = "0" if digest[0] != "0" else "1"
        s["capsule_digest"] = "".join(digest)
        run(
            "Signed capsule digest modified",
            original[:signature_start] + build_signature_trailer(s),
        )

    detected = sum(item["detected"] for item in results)

    return {
        "baseline": "VERIFIED",
        "attacks_run": len(results),
        "attacks_detected": detected,
        "all_attacks_detected": detected == len(results),
        "results": results,
        "note": (
            "This is a controlled tamper/authentication test set, "
            "not a proof of security against every possible attack."
        ),
    }
