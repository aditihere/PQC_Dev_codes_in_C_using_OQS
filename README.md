Post-Quantum Cryptography (PQC) Security Suite

A collection of hands-on, production-ready implementations for building quantum-resilient authentication, encryption, and communication systems.
This repository showcases practical usage of NIST-selected post-quantum algorithms such as Kyber (KEM) for key exchange and Dilithium (digital signatures), ensuring cryptographic security even in the era of large-scale quantum computing.

Features
1. PQC-Based Authentication for Cloud Applications

Secure client–server authentication using Dilithium signatures.

Python-based implementation leveraging liboqs bindings.

End-to-end example with key generation, signing, verification, and session establishment.

2. Post-Quantum Secure Key Exchange (Kyber)

Hybrid or standalone Kyber-based key encapsulation for secure channel setup.

Resistant to Shor’s and Grover’s algorithms.

Integrates easily into TLS-like workflows.

3. Post-Quantum Secure File Encryption Tool

Symmetric encryption (AES-256-GCM) with Kyber-protected key exchange.

CLI tool for file encryption/decryption.

Suitable for cloud storage and secure backups.

4. PQC-Based API Authentication

API request signing with Dilithium.

Tokenless, cryptographically-verified API access.

Prevents replay attacks and credential theft.

5. Quantum-Safe VPN & Encrypted Messaging

VPN tunnel establishment using Kyber for initial key agreement.

Encrypted peer-to-peer messaging with post-quantum keys.

Supports forward secrecy with frequent re-keying.

Tech Stack

Languages: Python (with liboqs), C (for low-level PQC bindings)

Libraries: Open Quantum Safe (liboqs), PyCryptodome, Flask

Algorithms: CRYSTALS-Kyber, CRYSTALS-Dilithium

Protocols: Hybrid encryption (Kyber + AES), PQC-enabled mutual authentication
