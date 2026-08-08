from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

APP_NAME = "AegisCrypt"
APP_VERSION = "0.9.2"
PROFILE_CHOICES = ["personal", "hardened", "archive"]


def _password(prompt: str = "Enter password: ") -> str:
    value = getpass.getpass(prompt)
    if not value:
        raise ValueError("Password/passphrase cannot be empty.")
    return value


def _new_password(label: str = "password") -> str:
    value = _password(f"Enter {label}: ")
    confirm = _password(f"Confirm {label}: ")
    if value != confirm:
        raise ValueError(f"{label.capitalize()} values do not match.")
    return value


def _print_json(data: dict) -> None:
    print(json.dumps(data, indent=2))


def _inspect_mode(path: Path) -> str:
    from verifier import inspect_file
    return inspect_file(path)["mode"]


def _credentials_for(path: Path, identity: Path | None) -> dict:
    mode = _inspect_mode(path)

    if mode == "recipient":
        if not identity:
            raise ValueError(
                "Recipient capsule requires --identity <private-key-file>."
            )
        return {
            "identity_path": identity,
            "identity_passphrase": _password(
                "Enter private-key passphrase: "
            ),
        }

    return {"password": _password()}


def cmd_profiles(args):
    from policy import PROFILES

    for p in PROFILES.values():
        print(f"{p.name}")
        print(f"  {p.description}")
        print(
            f"  Argon2id: time={p.argon2_time_cost}, "
            f"memory={p.argon2_memory_kib // 1024} MiB, "
            f"parallelism={p.argon2_parallelism}"
        )
        print()


def cmd_plan(args):
    from planner import compile_protection_plan, protection_plan_to_dict

    plan = compile_protection_plan(
        args.sensitivity,
        args.years,
        args.sharing,
        args.recovery,
        args.quantum,
    )
    _print_json(protection_plan_to_dict(plan))


def cmd_keygen(args):
    from keys import generate_identity

    passphrase = _new_password("private-key passphrase")
    pub, priv = generate_identity(
        args.name,
        passphrase,
        args.out,
    )
    print("Identity created.")
    print(f"Public key : {pub}")
    print(f"Private key: {priv}")


def cmd_encrypt(args):
    from encryptor import encrypt_password_file, encrypt_recipient_file

    if args.recipient:
        out = encrypt_recipient_file(
            args.input,
            [str(p) for p in args.recipient],
            args.output,
        )
        print(
            f"Encryption completed in recipient mode "
            f"({len(args.recipient)} recipient(s))."
        )
    else:
        password = _new_password("password")
        out = encrypt_password_file(
            args.input,
            password,
            args.profile,
            args.output,
        )
        print(
            f"Encryption completed in password mode "
            f"(profile={args.profile})."
        )

    print(f"Output: {out}")


def cmd_decrypt(args):
    from decryptor import decrypt_file

    creds = _credentials_for(args.input, args.identity)
    out = decrypt_file(
        args.input,
        output_path=args.output,
        **creds,
    )
    print("Decryption completed.")
    print(f"Output: {out}")
    print("Integrity: VERIFIED")


def cmd_inspect(args):
    from verifier import inspect_file
    _print_json(inspect_file(args.input))


def cmd_verify(args):
    from verifier import verify_file

    creds = _credentials_for(args.input, args.identity)
    _print_json(verify_file(args.input, **creds))


def cmd_receipt(args):
    from verifier import save_security_receipt

    creds = _credentials_for(args.input, args.identity)
    out = save_security_receipt(
        args.input,
        receipt_path=args.output,
        **creds,
    )
    print("Security receipt created.")
    print(f"Output: {out}")


def cmd_simulate(args):
    from simulator import simulate_attacks

    creds = _credentials_for(args.input, args.identity)
    report = simulate_attacks(args.input, **creds)

    print("AEGISCRYPT ATTACK SIMULATION")
    print("=" * 68)

    for item in report["results"]:
        status = "DETECTED" if item["detected"] else "FAILED"
        print(
            f"{item['attack']:<32} "
            f"{item['observed']:<10} {status}"
        )

    print("=" * 68)
    print(
        f"Detected: {report['attacks_detected']}/"
        f"{report['attacks_run']}"
    )
    print(
        "Result: "
        + (
            "ALL TESTED ATTACKS DETECTED"
            if report["all_attacks_detected"]
            else "ONE OR MORE TESTS FAILED"
        )
    )


def build_parser():
    parser = argparse.ArgumentParser(
        prog="aegis",
        description=(
            "AegisCrypt: policy-driven authenticated file encryption "
            "with password and multi-recipient public-key modes."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {APP_VERSION}",
    )

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    p = sub.add_parser("profiles")
    p.set_defaults(func=cmd_profiles)

    p = sub.add_parser("plan")
    p.add_argument(
        "--sensitivity",
        required=True,
        choices=["normal", "sensitive", "high"],
    )
    p.add_argument("--years", required=True, type=int)
    p.add_argument(
        "--sharing",
        required=True,
        choices=["none", "one", "many"],
    )
    p.add_argument(
        "--recovery",
        required=True,
        choices=["none", "single", "threshold"],
    )
    p.add_argument(
        "--quantum",
        required=True,
        choices=["no", "preferred", "required"],
    )
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("keygen")
    p.add_argument("--name", required=True)
    p.add_argument("--out", type=Path, default=Path("keys"))
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("encrypt")
    p.add_argument("input", type=Path)
    p.add_argument(
        "--profile",
        choices=PROFILE_CHOICES,
        default="personal",
    )
    p.add_argument(
        "--recipient",
        type=Path,
        action="append",
        help=(
            "Recipient public-key JSON. Repeat --recipient "
            "for multiple recipients."
        ),
    )
    p.add_argument("-o", "--output", type=Path)
    p.set_defaults(func=cmd_encrypt)

    for name, func in [
        ("decrypt", cmd_decrypt),
        ("verify", cmd_verify),
        ("receipt", cmd_receipt),
        ("simulate", cmd_simulate),
    ]:
        p = sub.add_parser(name)
        p.add_argument("input", type=Path)
        p.add_argument("--identity", type=Path)
        if name in {"decrypt", "receipt"}:
            p.add_argument("-o", "--output", type=Path)
        p.set_defaults(func=func)

    p = sub.add_parser("inspect")
    p.add_argument("input", type=Path)
    p.set_defaults(func=cmd_inspect)

    return parser


def main() -> int:
    args = build_parser().parse_args()

    try:
        args.func(args)
        return 0
    except KeyboardInterrupt:
        print("\nOperation cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
