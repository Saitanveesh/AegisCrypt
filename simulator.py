from __future__ import annotations

import json
import tempfile
from pathlib import Path

from container_format import PREFIX_SIZE, read_header
from util import b64d, b64e, canonical_json_bytes
from verifier import verify_file


def _verify(
    path: Path,
    password: str | None,
    identity_path: str | Path | None,
    identity_passphrase: str | None,
) -> bool:
    try:
        verify_file(
            path,
            password=password,
            identity_path=identity_path,
            identity_passphrase=identity_passphrase,
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
) -> dict:
    source = Path(input_path)

    if not _verify(
        source,
        password,
        identity_path,
        identity_passphrase,
    ):
        raise ValueError(
            "Baseline verification failed. Use the correct credential "
            "and an unmodified capsule."
        )

    original = source.read_bytes()
    _, header_bytes, header, payload_offset = read_header(source)
    results = []

    def run(name: str, mutated: bytes):
        with tempfile.NamedTemporaryFile(
            suffix=".aegis",
            delete=False,
        ) as f:
            temp_path = Path(f.name)
            f.write(mutated)

        try:
            accepted = _verify(
                temp_path,
                password,
                identity_path,
                identity_passphrase,
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
            original[:PREFIX_SIZE]
            + new_header
            + original[payload_offset:],
        )

    h = json.loads(header_bytes.decode("utf-8"))

    if h["mode"] == "password":
        wrapped = bytearray(
            b64d(h["key_management"]["wrapped_key"])
        )
        wrapped[0] ^= 1
        h["key_management"]["wrapped_key"] = b64e(bytes(wrapped))
    else:
        wrapped = bytearray(
            b64d(
                h["key_management"]["recipients"][0]["wrapped_key"]
            )
        )
        wrapped[0] ^= 1
        h["key_management"]["recipients"][0]["wrapped_key"] = b64e(
            bytes(wrapped)
        )

    new_header = canonical_json_bytes(h)

    if len(new_header) == len(header_bytes):
        run(
            "Wrapped data key modified",
            original[:PREFIX_SIZE]
            + new_header
            + original[payload_offset:],
        )

    mutated = bytearray(original)
    if payload_offset < len(mutated) - 16:
        mutated[payload_offset] ^= 1
        run("Ciphertext bit flipped", bytes(mutated))

    mutated = bytearray(original)
    mutated[-1] ^= 1
    run("Authentication tag modified", bytes(mutated))

    run("Capsule truncated", original[:-1])
    run("Extra byte appended", original + b"\x00")

    detected = sum(item["detected"] for item in results)

    return {
        "baseline": "VERIFIED",
        "attacks_run": len(results),
        "attacks_detected": detected,
        "all_attacks_detected": detected == len(results),
        "results": results,
        "note": (
            "This is a controlled tamper/authentication test set, "
            "not a proof of universal security."
        ),
    }
