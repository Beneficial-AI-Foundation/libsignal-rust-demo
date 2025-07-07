# LibSignal Rust Demo

A collection of examples demonstrating the core features of the Signal Protocol implementation in Rust. This project showcases key generation, X3DH key agreement, and sealed sender functionality using the [libsignal-protocol](https://github.com/signalapp/libsignal) library.

## 🔐 Overview

The Signal Protocol is a cryptographic protocol that provides end-to-end encryption for secure messaging. This repository contains practical examples showing how to:

- Generate and manage cryptographic keys (identity, pre-keys, ephemeral keys)
- Implement the X3DH key agreement protocol
- Create and verify digital signatures
- Use post-quantum cryptography (Kyber) for future-proof security
- Implement sealed sender messaging for metadata privacy

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone <repository-url>
cd libsignal-rust-demo
```

### 2. Build the Project
```bash
cargo build
```

### 3. Run Examples
Each example can be run individually:

```bash
# Basic key generation
cargo run --bin basic_session_keys

# Key generation with signatures
cargo run --bin basic_session_keys_signed

# X3DH key agreement protocol
cargo run --bin basic_session_x3dh

# Sealed sender demonstration
cargo run --bin sealed_sender_demo
```

## 📚 Examples

### 1. Basic Session Keys (`basic_session_keys.rs`)
**Purpose**: Demonstrates fundamental key generation and serialization.

**What it shows**:
- Identity key pair generation for two parties (Alice and Bob)
- Pre-key generation (classic and Kyber post-quantum)
- Protocol address creation
- Key serialization and display

**Key concepts**:
- `IdentityKeyPair`: Long-term identity keys
- `KeyPair`: Elliptic curve key pairs
- `kem::KeyPair`: Kyber post-quantum key pairs
- `ProtocolAddress`: User identification in the protocol

### 2. Basic Session Keys with Signatures (`basic_session_keys_signed.rs`)
**Purpose**: Builds on basic keys by adding digital signatures and pre-key bundles.

**What it shows**:
- All features from basic keys example
- Digital signature creation and verification
- Pre-key bundle construction
- Signature validation process

**Key concepts**:
- Digital signatures for authentication
- `PreKeyBundle`: Collection of public keys and signatures
- Signature verification for security

### 3. X3DH Key Agreement (`basic_session_x3dh.rs`)
**Purpose**: Demonstrates the complete X3DH (Extended Triple Diffie-Hellman) key agreement protocol.

**What it shows**:
- Complete X3DH protocol implementation
- Session establishment between Alice (initiator) and Bob (responder)
- Ephemeral key generation
- Post-quantum cryptography integration
- Session record creation and verification

**Key concepts**:
- X3DH protocol: The key agreement mechanism used by Signal
- `AliceSignalProtocolParameters`: Alice's side of the protocol
- `BobSignalProtocolParameters`: Bob's side of the protocol
- Session initialization and shared secret derivation
- Identity verification between parties

**Protocol flow**:
1. Alice generates ephemeral base key
2. Alice performs X3DH using Bob's pre-key bundle
3. Alice creates session record with derived secrets
4. Bob receives Alice's ephemeral key and Kyber ciphertext
5. Bob performs X3DH key agreement
6. Both parties verify they have matching session state

### 4. Sealed Sender Demo (`sealed_sender_demo.rs`)
**Purpose**: Demonstrates metadata-hiding message encryption using sealed sender.

**What it shows**:
- Server and sender certificate creation
- Protocol store management
- Sealed sender message encryption
- Sealed sender message decryption
- Metadata privacy protection

**Key concepts**:
- Sealed sender: Hides sender identity from intermediate servers
- `ServerCertificate` and `SenderCertificate`: Trust infrastructure
- `InMemSignalProtocolStore`: Protocol state management
- Metadata privacy and forward secrecy

## 🔧 Dependencies

- **libsignal-protocol**: Core Signal Protocol implementation
- **rand**: Cryptographically secure random number generation
- **hex**: Hexadecimal encoding for key display
- **env_logger**: Logging infrastructure for debugging
- **tokio**: Async runtime for the sealed sender example
- **futures**: Async programming utilities
- **uuid**: UUID generation for identifiers

## 🏗️ Project Structure

```
libsignal-rust-demo/
├── Cargo.toml              # Project configuration and dependencies
├── README.md               # This file
├── src/
│   ├── basic_session_keys.rs          # Basic key generation example
│   ├── basic_session_keys_signed.rs   # Keys with signatures example
│   ├── basic_session_x3dh.rs          # X3DH protocol demonstration
│   └── sealed_sender_demo.rs          # Sealed sender example
└── target/                 # Build artifacts (auto-generated)
```

## 🔒 Security Features Demonstrated

### Post-Quantum Cryptography
- **Kyber1024**: NIST-standardized post-quantum KEM (Key Encapsulation Mechanism)
- Future-proof against quantum computer attacks
- Hybrid security combining classical and post-quantum algorithms

### Forward Secrecy
- Ephemeral keys that are deleted after use
- Protection against key compromise
- Regular key rotation mechanisms

### Perfect Forward Secrecy
- Each message encrypted with unique keys
- Compromise of one message doesn't affect others
- Automatic key derivation and deletion

### Metadata Privacy
- Sealed sender hides sender identity from servers
- Protection against traffic analysis
- Minimal metadata exposure

## 🔍 Key Concepts Explained

### X3DH (Extended Triple Diffie-Hellman)
A key agreement protocol that enables two parties to establish a shared secret over an insecure channel. It provides:
- **Authentication**: Verifies the identity of both parties
- **Forward secrecy**: Past communications remain secure even if keys are compromised
- **Deniability**: Participants can deny having participated in the conversation

### Signal Protocol Components
- **Identity Keys**: Long-term keys tied to user identity
- **Pre-keys**: Medium-term keys published to a server
- **Ephemeral Keys**: Short-term keys used once per session
- **Kyber Keys**: Post-quantum keys for future security

### Security Properties
- **End-to-end encryption**: Only sender and recipient can read messages
- **Forward secrecy**: Past messages remain secure if current keys are compromised
- **Future secrecy**: Future messages remain secure if past keys are compromised
- **Deniability**: Cryptographic proof that messages could have been forged

## 🔗 Resources

- [Signal Protocol Documentation](https://signal.org/docs/)
- [libsignal Repository](https://github.com/signalapp/libsignal)
- [X3DH Specification](https://signal.org/docs/specifications/x3dh/)
- [Double Ratchet Specification](https://signal.org/docs/specifications/doubleratchet/)
- [Sealed Sender](https://signal.org/blog/sealed-sender/)

