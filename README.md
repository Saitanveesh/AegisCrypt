# AegisCrypt

AegisCrypt is a local desktop application for file encryption, decryption, recipient-based sharing, verification, and tamper testing.

I built it while studying Cryptography and Network Security because I wanted to understand what happens after the textbook diagrams: how keys are derived, how encrypted files are structured, how recipient access is handled, and what a program should do when encrypted data has been modified.

## What it does

AegisCrypt supports two ways to protect a file:

- **Password mode** uses Argon2id to derive a key-encryption key from the password.
- **Recipient mode** uses X25519 public/private key identities. A file can be encrypted for one recipient or several recipients without sharing a common password.

The file contents are encrypted with **AES-256-GCM**. Each file gets a fresh random data-encryption key. The original filename and file size are stored inside the encrypted payload rather than exposed as plain metadata.

The current build also includes:

- authenticated file encryption and decryption
- password profiles: Personal, Hardened, and Archive
- X25519 identity generation
- multi-recipient envelope encryption
- encrypted filename and size metadata
- capsule inspection and cryptographic verification
- JSON security receipts
- a controlled tamper-testing lab
- a policy planner for mapping requirements to the capabilities currently implemented
- a desktop interface built with HTML, CSS, JavaScript, Python, and PyWebView
- a command-line interface for testing and automation

## Main workflows

### Encrypt

Password protection and recipient-based protection are available from the same screen.

### Decrypt

The application detects the capsule mode and uses either the password or the selected private identity.

### Identities

Recipient identities use X25519. The public key can be shared; the private key file is protected with a passphrase.

### Inspect and verify

Inspection reads the public container information. Verification authenticates the encrypted capsule using the correct credential. A JSON receipt can be created after verification.

### Attack Lab

The Attack Lab makes controlled changes to a copy of an encrypted capsule and checks whether those changes are rejected. It covers cases such as a modified nonce, wrapped key, ciphertext, authentication tag, truncation, and appended data.

This is a test harness for the protections implemented in the project. It is not a claim that the application has been proven secure against every possible attack.

## How the encryption path works

### Password mode

```text
Password
   |
Argon2id
   |
Key-encryption key
   |
Wrap random file key
   |
AES-256-GCM file encryption
   |
.aegis capsule
```

### Recipient mode

```text
Recipient X25519 public key(s)
   |
Ephemeral X25519 key exchange
   |
HKDF-SHA256
   |
Wrap random file key for each recipient
   |
AES-256-GCM file encryption
   |
.aegis capsule
```

The same random file key is used to encrypt the payload once. Each authorized recipient receives a separate wrapped copy of that key.

## Project structure

```text
AegisCrypt/
├── ui/                    # Desktop interface
├── tests/                 # Regression and round-trip tests
├── keys/                  # Local identities; private files are ignored by Git
├── encrypted_files/       # Local encrypted output; ignored by Git
├── desktop.py             # PyWebView desktop bridge
├── main.py                # Command-line interface
├── encryptor.py           # Streaming file encryption
├── decryptor.py           # Verification and decryption path
├── envelope.py            # Password and recipient key wrapping
├── keys.py                # X25519 identity handling
├── kdf.py                 # Argon2id password derivation
├── verifier.py            # Inspection, verification, and receipts
├── simulator.py           # Controlled tamper tests
├── planner.py             # Protection policy planner
└── container_format.py    # .aegis container parsing
```

## Run on Windows

### Quick setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python desktop.py
```

The repository also includes:

```text
setup_windows.bat
run_desktop.bat
```

Run `setup_windows.bat` once, then use `run_desktop.bat` to start the desktop application.

### UI preview with VS Code Live Server

Open `ui/index.html` with Live Server if you only want to work on the interface.

Live Server cannot call the Python cryptographic engine. File encryption, decryption, key generation, and verification work when the interface is started through:

```powershell
python desktop.py
```

## CLI examples

Check the version:

```powershell
python main.py --version
```

Encrypt with a password:

```powershell
python main.py encrypt sample.txt --profile hardened
```

Create an identity:

```powershell
python main.py keygen --name alice
```

Encrypt for one recipient:

```powershell
python main.py encrypt sample.txt --recipient keys/alice.aegis-public.json
```

Encrypt for several recipients:

```powershell
python main.py encrypt sample.txt `
  --recipient keys/alice.aegis-public.json `
  --recipient keys/bob.aegis-public.json
```

Decrypt a recipient capsule:

```powershell
python main.py decrypt sample.txt.aegis --identity keys/alice.aegis-private.json
```

Inspect a capsule:

```powershell
python main.py inspect sample.txt.aegis
```

Run the tamper tests:

```powershell
python main.py simulate sample.txt.aegis
```

## Tests

Install the development dependencies:

```powershell
pip install -r requirements-dev.txt
pytest -q
```

The tests cover password round trips, multi-recipient round trips, the CLI version path, and the policy planner's handling of unsupported post-quantum requirements.

## Security notes

This is a learning and portfolio project, not an independently audited cryptographic product.

A few boundaries are intentional:

- no private identity files are included in this repository
- no encrypted user files or generated receipts are committed
- post-quantum key encapsulation is not implemented in this build
- threshold recovery is not implemented
- the project does not claim to be “unbreakable”

For anything high-value or production-critical, use established, independently reviewed cryptographic software and a threat model appropriate to the environment.

## Current version

**0.9.2**

The current version includes the desktop interface, the public-key recipient flow, the refined file format, the CLI startup fix, and the PyWebView recursion fix.
