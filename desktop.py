from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path

APP_VERSION = "0.9.2"
BASE_DIR = Path(__file__).resolve().parent


class DesktopAPI:
    def _ok(self, **data):
        return {"ok": True, **data}

    def _error(self, exc):
        return {"ok": False, "error": str(exc)}

    def status(self):
        return self._ok(
            version=APP_VERSION,
            product="AegisCrypt Desktop",
            quantum_safe=False,
            capabilities=[
                "Password encryption",
                "X25519 recipient encryption",
                "Multi-recipient encryption",
                "Encrypted metadata",
                "Verification",
                "Security receipts",
                "Attack simulation",
                "Policy planning",
            ],
        )

    def pick_file(self):
        try:
            import webview

            if not webview.windows:
                raise RuntimeError("Desktop window is not ready.")

            window = webview.windows[0]
            result = window.create_file_dialog(
                webview.FileDialog.OPEN,
                allow_multiple=False,
            )

            if not result:
                return self._ok(path=None)

            return self._ok(path=str(result[0]))
        except Exception as exc:
            return self._error(exc)

    def pick_private_identity(self):
        return self.pick_file()

    def pick_public_identities(self):
        try:
            import webview

            if not webview.windows:
                raise RuntimeError("Desktop window is not ready.")

            window = webview.windows[0]
            result = window.create_file_dialog(
                webview.FileDialog.OPEN,
                allow_multiple=True,
            )

            return self._ok(
                paths=[str(p) for p in result] if result else []
            )
        except Exception as exc:
            return self._error(exc)

    def generate_identity(self, name, passphrase):
        try:
            from keys import generate_identity

            pub, priv = generate_identity(
                name,
                passphrase,
                BASE_DIR / "keys",
            )
            return self._ok(
                public_key=str(pub),
                private_key=str(priv),
            )
        except Exception as exc:
            return self._error(exc)

    def encrypt_password(self, input_path, password, profile):
        try:
            from encryptor import encrypt_password_file
            from util import unique_path

            source = Path(input_path)
            output = unique_path(
                source.with_name(source.name + ".aegis")
            )
            result = encrypt_password_file(
                source,
                password,
                profile,
                output,
            )
            return self._ok(output=str(result))
        except Exception as exc:
            return self._error(exc)

    def encrypt_recipients(self, input_path, public_keys):
        try:
            from encryptor import encrypt_recipient_file
            from util import unique_path

            source = Path(input_path)
            output = unique_path(
                source.with_name(source.name + ".aegis")
            )
            result = encrypt_recipient_file(
                source,
                list(public_keys),
                output,
            )
            return self._ok(output=str(result))
        except Exception as exc:
            return self._error(exc)

    def inspect_capsule(self, input_path):
        try:
            from verifier import inspect_file
            return self._ok(report=inspect_file(input_path))
        except Exception as exc:
            return self._error(exc)

    def verify_capsule(
        self,
        input_path,
        password=None,
        identity_path=None,
        identity_passphrase=None,
    ):
        try:
            from verifier import inspect_file, verify_file

            mode = inspect_file(input_path)["mode"]

            if mode == "password":
                report = verify_file(
                    input_path,
                    password=password,
                )
            else:
                report = verify_file(
                    input_path,
                    identity_path=identity_path,
                    identity_passphrase=identity_passphrase,
                )

            return self._ok(report=report)
        except Exception as exc:
            return self._error(exc)

    def decrypt_capsule(
        self,
        input_path,
        password=None,
        identity_path=None,
        identity_passphrase=None,
    ):
        try:
            from decryptor import decrypt_file
            from verifier import inspect_file

            mode = inspect_file(input_path)["mode"]

            if mode == "password":
                output = decrypt_file(
                    input_path,
                    password=password,
                )
            else:
                output = decrypt_file(
                    input_path,
                    identity_path=identity_path,
                    identity_passphrase=identity_passphrase,
                )

            return self._ok(output=str(output))
        except Exception as exc:
            return self._error(exc)

    def create_receipt(
        self,
        input_path,
        password=None,
        identity_path=None,
        identity_passphrase=None,
    ):
        try:
            from verifier import inspect_file, save_security_receipt
            from util import unique_path

            source = Path(input_path)
            receipt_path = unique_path(
                source.with_name(
                    source.name + ".receipt.json"
                )
            )

            mode = inspect_file(input_path)["mode"]

            if mode == "password":
                output = save_security_receipt(
                    input_path,
                    password=password,
                    receipt_path=receipt_path,
                )
            else:
                output = save_security_receipt(
                    input_path,
                    identity_path=identity_path,
                    identity_passphrase=identity_passphrase,
                    receipt_path=receipt_path,
                )

            return self._ok(output=str(output))
        except Exception as exc:
            return self._error(exc)

    def simulate(
        self,
        input_path,
        password=None,
        identity_path=None,
        identity_passphrase=None,
    ):
        try:
            from simulator import simulate_attacks
            from verifier import inspect_file

            mode = inspect_file(input_path)["mode"]

            if mode == "password":
                report = simulate_attacks(
                    input_path,
                    password=password,
                )
            else:
                report = simulate_attacks(
                    input_path,
                    identity_path=identity_path,
                    identity_passphrase=identity_passphrase,
                )

            return self._ok(report=report)
        except Exception as exc:
            return self._error(exc)

    def plan(
        self,
        sensitivity,
        years,
        sharing,
        recovery,
        quantum,
    ):
        try:
            from planner import (
                compile_protection_plan,
                protection_plan_to_dict,
            )

            plan = compile_protection_plan(
                sensitivity,
                int(years),
                sharing,
                recovery,
                quantum,
            )
            return self._ok(
                plan=protection_plan_to_dict(plan)
            )
        except Exception as exc:
            return self._error(exc)

    def reveal_path(self, path):
        try:
            target = Path(path).resolve()

            if platform.system() == "Windows":
                if target.is_file():
                    subprocess.run(
                        ["explorer", "/select,", str(target)],
                        check=False,
                    )
                else:
                    os.startfile(str(target))
            elif platform.system() == "Darwin":
                subprocess.run(["open", "-R", str(target)], check=False)
            else:
                subprocess.run(
                    ["xdg-open", str(target.parent)],
                    check=False,
                )

            return self._ok()
        except Exception as exc:
            return self._error(exc)


def main():
    try:
        import webview
    except ImportError:
        raise SystemExit(
            "pywebview is not installed. Run: pip install -r requirements.txt"
        )

    api = DesktopAPI()
    ui_path = (BASE_DIR / "ui" / "index.html").resolve()

    window = webview.create_window(
        "AegisCrypt",
        ui_path.as_uri(),
        js_api=api,
        width=1280,
        height=820,
        min_size=(980, 680),
    )
    webview.start(debug=False)


if __name__ == "__main__":
    main()
