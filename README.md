🛡️ Post-Quantum Security Toolkit

This repo is a hands-on collection of real-world examples showing how to build applications that can stand up to the cryptographic challenges of the quantum era.
From authentication systems to secure file sharing and encrypted messaging, everything here is designed to give you practical, working code for quantum-safe deployments — no toy examples, no skipped steps.

🔹 What’s Inside
1. PQC-based Authentication for Cloud Apps

A working setup for authenticating clients and servers using the Dilithium signature scheme.
Keys are generated, signatures are created and verified, and secure sessions are established — all in one flow.

2. Kyber-Powered Secure Key Exchange

An implementation of the Kyber KEM that can be used alone or in a hybrid mode alongside classical encryption.
Perfect for replacing RSA/ECC in any protocol that needs a future-proof handshake.

3. Quantum-Safe File Encryption Tool

A simple command-line tool for encrypting and decrypting files with AES-256-GCM, where the symmetric key is exchanged securely via Kyber.
Ideal for cloud storage or long-term backups.

4. API Authentication Without Secrets

API requests are signed using Dilithium, so there’s no need for static tokens.
It’s fast, verifiable, and immune to replay attacks.

5. Encrypted Messaging & VPN with PQC Keys

A demo of how to establish VPN tunnels and peer-to-peer messaging channels using Kyber for the key exchange.
Supports forward secrecy by re-keying regularly.

📚 Built With

Languages: Python, C

Libraries: liboqs (Open Quantum Safe), PyCryptodome, Flask

Algorithms: CRYSTALS-Kyber, CRYSTALS-Dilithium

Protocols: Hybrid encryption (Kyber + AES), PQC-based mutual auth
