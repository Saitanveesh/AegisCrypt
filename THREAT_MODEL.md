# Threat model

AegisCrypt is designed for local file protection and controlled sharing. This document states the boundaries the code assumes instead of hiding them behind a reassuring lock icon.

## Intended protections

AegisCrypt aims to detect unauthorized modification of an `.aegis` capsule and keep file contents confidential when the attacker does not possess the required password or recipient private key.

For signed capsules, it also checks that the encrypted artifact matches the Ed25519 signing key recorded in the signature trailer.

## Password assumptions

Password mode cannot make a weak password strong. Argon2id increases the cost of offline password guessing, but an attacker who obtains the capsule can still attempt guesses locally.

The password is not stored in the capsule.

## Private-key assumptions

Recipient and signing private keys are encrypted at rest with a passphrase in the AegisCrypt private-identity file. If an attacker obtains both the unlocked private key and the protected capsule, recipient confidentiality is lost for that identity.

Version 7 does not yet bind private keys to TPM, Secure Enclave, smart card, or HSM hardware.

## Sender identity and trust

A valid Ed25519 signature establishes continuity with a signing key. It does not by itself prove the legal or real-world identity of the person controlling that key.

Users should verify fingerprints through an independent trusted channel before marking a contact as trusted.

## Local machine compromise

AegisCrypt does not defend against an attacker who already controls the operating system, captures keystrokes, reads process memory, replaces the application binary, or monitors plaintext while the user opens it.

## Availability

Encryption does not guarantee availability. Losing a password or private key can make data permanently inaccessible. Threshold recovery is not implemented in version 7.

## Post-quantum status

AegisCrypt 7 does not implement post-quantum key encapsulation. The policy planner reports this as a missing capability when requested.

## Attack Lab scope

Attack Lab checks a defined set of malformed or modified capsule cases. Passing those cases does not prove the absence of implementation flaws, cryptographic design problems, side channels, dependency vulnerabilities, or attacks outside the tested model.
