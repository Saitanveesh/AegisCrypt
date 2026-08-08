# Security notes

AegisCrypt is an educational and portfolio project. It has not undergone an independent professional security audit and should not be treated as a replacement for established, reviewed encryption products in high-risk environments.

## Sensitive files

The repository is configured to ignore:

- private identity files
- `.aegis` encrypted files
- generated security receipts
- virtual environments and local configuration

Do not commit real private keys, passphrases, or confidential test data.

## Reporting a problem

If you find a security problem in the code, avoid posting real keys, passwords, or sensitive files in a public issue. Describe the behavior and the affected component without including secrets.

## Current limitations

The present build does not provide post-quantum key encapsulation, threshold recovery, hardware-backed key storage, or an external security audit.
