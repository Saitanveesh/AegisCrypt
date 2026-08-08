from __future__ import annotations

from pathlib import Path
import tempfile

from decryptor import decrypt_file
from encryptor import encrypt_password_file, encrypt_recipient_file
from keys import generate_identity
from planner import compile_protection_plan
from verifier import verify_file


def test_password_roundtrip():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        source = td / "hello.txt"
        source.write_text("hello", encoding="utf-8")

        capsule = encrypt_password_file(
            source,
            "CorrectHorseBatteryStaple!",
            "personal",
        )

        verify_file(
            capsule,
            password="CorrectHorseBatteryStaple!",
        )

        out = decrypt_file(
            capsule,
            password="CorrectHorseBatteryStaple!",
        )

        assert out.read_text(encoding="utf-8") == "hello"


def test_two_recipient_roundtrip():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        source = td / "hello.txt"
        source.write_text("recipient data", encoding="utf-8")

        pub_a, priv_a = generate_identity(
            "alice",
            "AlicePrivateKeyPassphrase!",
            td / "keys",
        )
        pub_b, priv_b = generate_identity(
            "bob",
            "BobPrivateKeyPassphrase!",
            td / "keys",
        )

        capsule = encrypt_recipient_file(
            source,
            [str(pub_a), str(pub_b)],
        )

        report = verify_file(
            capsule,
            identity_path=priv_a,
            identity_passphrase="AlicePrivateKeyPassphrase!",
        )

        out = decrypt_file(
            capsule,
            identity_path=priv_b,
            identity_passphrase="BobPrivateKeyPassphrase!",
        )

        assert report["recipient_count"] == 2
        assert out.read_text(encoding="utf-8") == "recipient data"


def test_planner_does_not_fake_post_quantum_support():
    plan = compile_protection_plan(
        "high",
        15,
        "many",
        "threshold",
        "required",
    )

    assert plan.ready_now is False
    assert any(
        "post-quantum" in item.lower()
        for item in plan.missing_capabilities
    )
