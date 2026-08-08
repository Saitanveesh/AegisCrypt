from __future__ import annotations

from dataclasses import asdict, dataclass

from policy import recommend_profile


@dataclass(frozen=True)
class ProtectionPlan:
    profile: str
    ready_now: bool
    recommended_mode: str
    sender_signature_recommended: bool
    current_capabilities: list[str]
    missing_capabilities: list[str]
    rationale: list[str]


def compile_protection_plan(
    sensitivity: str,
    retention_years: int,
    sharing: str,
    recovery: str,
    quantum: str,
) -> ProtectionPlan:
    profile = recommend_profile(sensitivity, retention_years)
    sharing = sharing.lower()
    recovery = recovery.lower()
    quantum = quantum.lower()

    if sharing not in {"none", "one", "many"}:
        raise ValueError("Sharing must be: none, one, or many.")
    if recovery not in {"none", "single", "threshold"}:
        raise ValueError("Recovery must be: none, single, or threshold.")
    if quantum not in {"no", "preferred", "required"}:
        raise ValueError("Quantum must be: no, preferred, or required.")

    current = [
        "AES-256-GCM authenticated streaming file encryption",
        "Argon2id password protection",
        "X25519 public-key recipient encryption",
        "Multi-recipient envelope encryption",
        "Ed25519 sender signatures",
        "Local contact trust states",
        "Encrypted filename and size metadata",
        "Security receipts and verification",
        "Controlled tamper simulation",
    ]

    missing: list[str] = []
    rationale = [
        f"Base password profile: {profile.name} "
        f"(sensitivity={sensitivity}, retention={retention_years} years)."
    ]

    if sharing == "none":
        recommended_mode = "password"
        rationale.append("Local-only protection can use password mode.")
    else:
        recommended_mode = "recipient"
        rationale.append(
            "Recipient mode avoids sharing one password between multiple people."
        )

    sender_signature_recommended = sharing != "none" or sensitivity in {"sensitive", "high"}
    if sender_signature_recommended:
        rationale.append(
            "A sender signature is recommended so recipients can verify who produced the capsule."
        )

    if recovery == "single":
        missing.append("Dedicated recovery-key mechanism")
    elif recovery == "threshold":
        missing.append("Threshold recovery shares")

    if quantum == "preferred":
        missing.append("Hybrid classical + post-quantum recipient protection")
    elif quantum == "required":
        missing.extend(
            [
                "Mandatory hybrid classical + post-quantum recipient protection",
                "Downgrade prevention for post-quantum policy",
            ]
        )

    return ProtectionPlan(
        profile=profile.name,
        ready_now=not missing,
        recommended_mode=recommended_mode,
        sender_signature_recommended=sender_signature_recommended,
        current_capabilities=current,
        missing_capabilities=missing,
        rationale=rationale,
    )


def protection_plan_to_dict(plan: ProtectionPlan) -> dict:
    return asdict(plan)
