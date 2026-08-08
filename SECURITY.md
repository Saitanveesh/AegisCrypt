# Security

AegisCrypt is an educational and portfolio project. Version 7 adds stronger authenticity and testing features, but the project has not undergone an independent professional security audit.

## Do not publish secrets

The repository ignores private identity files, `.aegis` files, generated receipts, virtual environments, and local configuration. Do not commit real passphrases, private keys, confidential plaintext, or sensitive encrypted artifacts.

## Reporting a security problem

Do not paste real keys, passwords, private files, or confidential data into a public GitHub issue.

A useful report should identify the affected component, the behavior you expected, the behavior you observed, and a minimal reproduction that contains no real secrets.

## Current limitations

AegisCrypt 7 does not provide:

- post-quantum key encapsulation
- threshold recovery
- hardware-backed private keys
- independent security certification

See `THREAT_MODEL.md` for the assumptions behind the current implementation.
