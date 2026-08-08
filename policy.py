from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityProfile:
    profile_id: int
    name: str
    description: str
    argon2_time_cost: int
    argon2_memory_kib: int
    argon2_parallelism: int


PROFILES = {
    "personal": SecurityProfile(
        1,
        "personal",
        "Balanced password protection for normal private files.",
        3,
        65536,
        4,
    ),
    "hardened": SecurityProfile(
        2,
        "hardened",
        "Higher password-cracking cost for sensitive files.",
        4,
        131072,
        4,
    ),
    "archive": SecurityProfile(
        3,
        "archive",
        "Higher-cost password protection for important long-term local archives.",
        4,
        262144,
        4,
    ),
}


def get_profile(name: str) -> SecurityProfile:
    try:
        return PROFILES[name.lower()]
    except KeyError as exc:
        raise ValueError(
            f"Unknown profile '{name}'. Valid profiles: {', '.join(PROFILES)}"
        ) from exc


def recommend_profile(sensitivity: str, retention_years: int) -> SecurityProfile:
    sensitivity = sensitivity.strip().lower()

    if sensitivity not in {"normal", "sensitive", "high"}:
        raise ValueError("Sensitivity must be: normal, sensitive, or high.")

    if retention_years < 0:
        raise ValueError("Retention years cannot be negative.")

    if sensitivity == "high" or retention_years >= 10:
        return PROFILES["archive"]

    if sensitivity == "sensitive" or retention_years >= 3:
        return PROFILES["hardened"]

    return PROFILES["personal"]
