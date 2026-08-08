from __future__ import annotations

import os

from argon2.low_level import Type, hash_secret_raw

from policy import SecurityProfile

SALT_SIZE = 16
KEY_SIZE = 32


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def derive_password_key(
    password: str,
    salt: bytes,
    profile: SecurityProfile,
) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("Password/passphrase cannot be empty.")

    if not isinstance(salt, bytes) or len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be exactly {SALT_SIZE} bytes.")

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=profile.argon2_time_cost,
        memory_cost=profile.argon2_memory_kib,
        parallelism=profile.argon2_parallelism,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )
