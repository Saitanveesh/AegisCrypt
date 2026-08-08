# AegisCrypt 7

AegisCrypt is a local desktop application for authenticated file encryption, recipient-based sharing, sender verification, security receipts, and controlled tamper testing.

I started the project while studying Cryptography and Network Security because I wanted to understand what happens after the diagrams: how file keys are created, how passwords protect those keys, how several recipients can open the same encrypted file, how a recipient can verify who sent it, and how the application should behave when an encrypted artifact has been changed.

Version **7.0.0** is a major rebuild of that idea. It keeps the application local-first and adds sender signatures, contact trust states, a versioned signature trailer, richer security receipts, a larger Attack Lab, and compatibility with the version-4 `.aegis` capsules produced by the earlier public build.

## What AegisCrypt 7 does

### File protection

- AES-256-GCM authenticated streaming encryption
- fresh random data-encryption key for every file
- encrypted original filename and file-size metadata
- atomic output writes and no silent overwrite of existing files
- authentication pass before plaintext is written during decryption

### Password mode

- Argon2id password-based key derivation
- Personal, Hardened, and Archive profiles
- the password protects a random file key rather than being used directly as the file-encryption key

### Recipient mode

- X25519 public/private encryption identities
- HKDF-SHA256 derived wrapping keys
- one encrypted payload with separately wrapped access for each recipient
- single and multi-recipient sharing without a shared password

### Sender authenticity

AegisCrypt 7 identities now contain two independent key pairs:

- X25519 for recipient access
- Ed25519 for sender signatures

A capsule can be signed after encryption. Verification checks the signature, the capsule digest, and the signing-key fingerprint. The application also reports the local trust state of the signer when that public identity has been imported as a contact.

A valid signature proves that the capsule matches the signing key embedded in the signed record. Trust in the person behind that key still depends on verifying the fingerprint through an appropriate channel.

### Local contact trust

Public identities can be imported into a local contact store with one of three states:

- `unverified`
- `trusted`
- `blocked`

A cryptographically valid capsule from a locally blocked signing identity is rejected by verification.

### Inspect, verify, and receipts

Inspection shows the public structure of a capsule without decrypting its contents. Verification checks the encrypted payload and, when present, the sender signature.

Security Receipt v2 records information such as:

- capsule SHA-256
- container version
- encryption mode
- recipient count
- authentication result
- sender-signature result
- signing fingerprint
- local trust state
- verification timestamp
- AegisCrypt version used for verification

Receipts never contain passwords, private keys, or plaintext file metadata.

### Attack Lab

The Attack Lab works on temporary copies and checks whether the application rejects controlled changes such as:

- container-version changes
- nonce changes
- wrapped-key changes
- ciphertext bit flips
- authentication-tag changes
- truncation
- appended data
- sender-signature changes
- signing-public-key changes
- signed-digest changes

The result is evidence about the test cases implemented in the project. It is not a mathematical proof that AegisCrypt is secure against every possible attack.

## Encryption paths

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
Optional Ed25519 sender signature
   |
.aegis capsule
```

### Recipient mode

```text
Recipient X25519 public identity(s)
   |
Ephemeral X25519 key exchange
   |
HKDF-SHA256
   |
Wrap the random file key for each recipient
   |
AES-256-GCM file encryption
   |
Optional Ed25519 sender signature
   |
.aegis capsule
```

The payload is encrypted once. Each authorized recipient gets a separate wrapped copy of the same random file key.

## Run the desktop application

Windows / VS Code terminal:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python desktop.py
```

The repository also includes `setup_windows.bat` and `run_desktop.bat`.

VS Code Live Server can preview `ui/index.html`, but file and key operations require `python desktop.py` because the browser preview does not have access to the Python engine.

## Useful CLI commands

Check the release:

```powershell
python main.py --version
```

Create a v7 identity:

```powershell
python main.py keygen --name alice
```

Encrypt with a password and sign the capsule:

```powershell
python main.py encrypt report.pdf --profile hardened --sign-with keys/alice.aegis-private.json
```

Encrypt for two recipients and sign as Alice:

```powershell
python main.py encrypt report.pdf `
  --recipient keys/alice.aegis-public.json `
  --recipient keys/bob.aegis-public.json `
  --sign-with keys/alice.aegis-private.json
```

Import Alice's public identity and mark it trusted:

```powershell
python main.py contact-import keys/alice.aegis-public.json --trust trusted
```

Verify a recipient capsule:

```powershell
python main.py verify report.pdf.aegis --identity keys/bob.aegis-private.json
```

Run the Attack Lab:

```powershell
python main.py simulate report.pdf.aegis --identity keys/bob.aegis-private.json
```

## Format compatibility

AegisCrypt 7 writes container version **5**. The reader also accepts the unsigned version-4 capsules produced by the previous public build so existing test data does not become useless merely because someone discovered version numbers.

The version-5 container adds a mandatory canonical signature trailer. Unsigned capsules contain an explicit unsigned trailer; signed capsules contain the Ed25519 signature record.

See [`FORMAT.md`](FORMAT.md) for the container layout and [`THREAT_MODEL.md`](THREAT_MODEL.md) for the security assumptions.

## Tests

```powershell
pip install -r requirements-dev.txt
pytest -q
```

The suite covers password round trips, signed multi-recipient round trips, local trust states, blocked signers, Attack Lab tamper cases, the policy planner, CLI startup, and version-4 compatibility.

## Deliberate limits

AegisCrypt 7 does **not** claim to be unbreakable, certified, or independently audited.

The current build does not implement:

- post-quantum key encapsulation
- threshold recovery
- hardware-backed private keys
- enterprise key escrow

Those items are not represented as active protection in the UI or policy planner. A security tool lying about what it protects would be an unusually efficient way to defeat its own purpose.

For high-value or production-critical data, use established, independently reviewed cryptographic software and a threat model appropriate to the environment.
