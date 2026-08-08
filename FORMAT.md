# AegisCrypt capsule format

This document describes the file format written by AegisCrypt 7.0.0.

## Version 5 layout

```text
+------------------------------+
| Prefix                       |
| magic = AEGIS                |
| container version = 5        |
| header length                |
+------------------------------+
| Canonical JSON header        |
+------------------------------+
| AES-GCM ciphertext           |
| (encrypted metadata + file)  |
+------------------------------+
| 16-byte AES-GCM tag          |
+------------------------------+
| Canonical signature JSON     |
+------------------------------+
| signature JSON length        |
| magic = ASIG                 |
+------------------------------+
```

The prefix and canonical JSON header are used as AES-GCM additional authenticated data.

The encrypted plaintext begins with a length-prefixed JSON metadata object containing the original basename and original size, followed by the file bytes.

## Key management

### Password mode

Argon2id derives a key-encryption key from the user password and a fresh random salt. AES-GCM wraps the random 256-bit file data-encryption key.

### Recipient mode

Each recipient gets a separate stanza containing an ephemeral X25519 public key, a fresh wrap nonce, and the wrapped file key. X25519 shared secrets are passed through HKDF-SHA256 before being used as wrapping keys.

The payload itself is encrypted only once.

## Sender signature trailer

Version 5 always carries a signature trailer.

Unsigned capsules contain:

```json
{
  "format": "AEGIS-SIGNATURE",
  "signed": false,
  "version": 1
}
```

Signed capsules include the sender name, Ed25519 public signing key, signing fingerprint, SHA-256 digest of the capsule bytes through the AES-GCM tag, and the Ed25519 signature.

The signature is computed over a domain-separated capsule digest rather than loading the entire file into memory.

## Version 4 compatibility

AegisCrypt 7 accepts version-4 capsules created by the previous public build. Version 4 has no signature trailer and is reported as unsigned.
