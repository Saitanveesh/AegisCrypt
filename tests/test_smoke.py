from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from container_format import MAGIC, PREFIX_STRUCT
from decryptor import decrypt_file
from encryptor import encrypt_password_file, encrypt_recipient_file
from envelope import wrap_key_with_password
from keys import generate_identity
from planner import compile_protection_plan
from simulator import simulate_attacks
from trust_store import import_contact, set_contact_trust
from util import b64e, canonical_json_bytes
from verifier import verify_file


def test_password_roundtrip_unsigned():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        source = td / "hello.txt"
        source.write_text("hello v7", encoding="utf-8")

        capsule = encrypt_password_file(
            source,
            "CorrectHorseBatteryStaple!",
            "personal",
        )

        report = verify_file(
            capsule,
            password="CorrectHorseBatteryStaple!",
            trust_store_path=td / "contacts.json",
        )
        out = decrypt_file(
            capsule,
            password="CorrectHorseBatteryStaple!",
        )

        assert out.read_text(encoding="utf-8") == "hello v7"
        assert report["verification_status"] == "VERIFIED"
        assert report["signature_status"] == "UNSIGNED"
        assert report["container_version"] == 5


def test_signed_two_recipient_roundtrip_and_trust():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        source = td / "report.txt"
        source.write_text("recipient data", encoding="utf-8")
        keys_dir = td / "keys"

        alice_pub, alice_priv = generate_identity(
            "Alice",
            "AlicePrivateKeyPassphrase!",
            keys_dir,
        )
        bob_pub, bob_priv = generate_identity(
            "Bob",
            "BobPrivateKeyPassphrase!",
            keys_dir,
        )

        trust_path = td / "contacts.json"
        contact = import_contact(
            alice_pub,
            trust="trusted",
            store_path=trust_path,
        )

        capsule = encrypt_recipient_file(
            source,
            [str(alice_pub), str(bob_pub)],
            signer_identity_path=alice_priv,
            signer_passphrase="AlicePrivateKeyPassphrase!",
        )

        report = verify_file(
            capsule,
            identity_path=bob_priv,
            identity_passphrase="BobPrivateKeyPassphrase!",
            trust_store_path=trust_path,
        )
        out = decrypt_file(
            capsule,
            identity_path=bob_priv,
            identity_passphrase="BobPrivateKeyPassphrase!",
            trust_store_path=trust_path,
        )

        assert out.read_text(encoding="utf-8") == "recipient data"
        assert report["recipient_count"] == 2
        assert report["signature_status"] == "VALID"
        assert report["trust_status"] == "trusted"
        assert report["signer_name"] == "Alice"
        assert contact["name"] == "Alice"


def test_blocked_signer_is_rejected():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        source = td / "blocked.txt"
        source.write_text("blocked sender", encoding="utf-8")

        pub, priv = generate_identity("Mallory", "PrivateKeyPass!", td / "keys")
        trust_path = td / "contacts.json"
        contact = import_contact(pub, trust="trusted", store_path=trust_path)
        fp = contact["signing_fingerprint"]
        set_contact_trust(fp, "blocked", store_path=trust_path)

        capsule = encrypt_password_file(
            source,
            "DataPassword!",
            signer_identity_path=priv,
            signer_passphrase="PrivateKeyPass!",
        )

        try:
            verify_file(
                capsule,
                password="DataPassword!",
                trust_store_path=trust_path,
            )
        except ValueError as exc:
            assert "blocked" in str(exc).lower()
        else:
            raise AssertionError("Blocked signer should have been rejected")


def test_attack_lab_detects_signed_capsule_tampering():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        source = td / "attack.txt"
        source.write_text("attack me", encoding="utf-8")
        _, priv = generate_identity("Signer", "SignerPass!", td / "keys")

        capsule = encrypt_password_file(
            source,
            "DataPass!",
            signer_identity_path=priv,
            signer_passphrase="SignerPass!",
        )

        report = simulate_attacks(
            capsule,
            password="DataPass!",
            trust_store_path=td / "contacts.json",
        )

        assert report["attacks_run"] >= 11
        assert report["all_attacks_detected"] is True


def test_planner_does_not_fake_post_quantum_support():
    plan = compile_protection_plan(
        "high",
        15,
        "many",
        "threshold",
        "required",
    )

    assert plan.ready_now is False
    assert plan.sender_signature_recommended is True
    assert any(
        "post-quantum" in item.lower()
        for item in plan.missing_capabilities
    )


def test_legacy_v4_password_capsule_remains_readable():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        source = td / "legacy.txt"
        plaintext = b"legacy-v4-data"
        source.write_bytes(plaintext)

        password = "LegacyPassword!"
        data_key = os.urandom(32)
        payload_nonce = os.urandom(12)
        key_management = wrap_key_with_password(data_key, password, "personal")
        header = {
            "mode": "password",
            "payload": {
                "algorithm": "AES-256-GCM",
                "nonce": b64e(payload_nonce),
            },
            "key_management": key_management,
            "metadata": "encrypted",
        }
        header_bytes = canonical_json_bytes(header)
        prefix = PREFIX_STRUCT.pack(MAGIC, 4, len(header_bytes))
        metadata = canonical_json_bytes(
            {"original_name": source.name, "original_size": len(plaintext)}
        )
        protected_plaintext = struct.pack(">I", len(metadata)) + metadata + plaintext
        ciphertext_and_tag = AESGCM(data_key).encrypt(
            payload_nonce,
            protected_plaintext,
            prefix + header_bytes,
        )

        capsule = td / "legacy.aegis"
        capsule.write_bytes(prefix + header_bytes + ciphertext_and_tag)

        report = verify_file(
            capsule,
            password=password,
            trust_store_path=td / "contacts.json",
        )
        out = decrypt_file(capsule, password=password)

        assert report["container_version"] == 4
        assert report["signature_status"] == "UNSIGNED"
        assert out.read_bytes() == plaintext
