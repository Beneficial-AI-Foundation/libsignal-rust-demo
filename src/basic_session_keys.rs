//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol::{
    DeviceId, IdentityKeyPair, KeyPair, PreKeyId, ProtocolAddress, SignedPreKeyId, kem,
};
use rand::Rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("=== LibSignal Basic Key Generation Example ===\n");

    // Generate identity keys for Alice and Bob
    let mut rng = rand::rng();
    let alice_identity_key_pair = IdentityKeyPair::generate(&mut rng);
    let bob_identity_key_pair = IdentityKeyPair::generate(&mut rng);

    println!("Generated identity keys:");
    println!("Alice: {}", hex::encode(alice_identity_key_pair.public_key().serialize()));
    println!("Bob:   {}", hex::encode(bob_identity_key_pair.public_key().serialize()));
    println!();

    // Generate pre-keys for Bob
    let pre_key_id = PreKeyId::from(rng.random::<u32>());
    let signed_pre_key_id = SignedPreKeyId::from(rng.random::<u32>());
    
    let pre_key_pair = KeyPair::generate(&mut rng);
    let signed_pre_key_pair = KeyPair::generate(&mut rng);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    
    println!("Generated pre-keys for Bob:");
    println!("  PreKey ID: {}", pre_key_id);
    println!("  SignedPreKey ID: {}", signed_pre_key_id);
    println!("  KyberPreKey (serialized): {}", hex::encode(kyber_pre_key_pair.public_key.serialize()));
    println!();

    // Set up addresses for Alice and Bob
    let alice_address = ProtocolAddress::new("alice".to_string(), DeviceId::try_from(1u32).unwrap());
    let bob_address = ProtocolAddress::new("bob".to_string(), DeviceId::try_from(2u32).unwrap());

    println!("Protocol addresses:");
    println!("Alice: {}", alice_address);
    println!("Bob:   {}", bob_address);
    println!();

    // Demonstrate key serialization
    println!("Key serialization examples:");
    println!("Alice's public key: {}", hex::encode(alice_identity_key_pair.public_key().serialize()));
    println!("Bob's public key: {}", hex::encode(bob_identity_key_pair.public_key().serialize()));
    println!("Pre-key public: {}", hex::encode(pre_key_pair.public_key.serialize()));
    println!("Signed pre-key public: {}", hex::encode(signed_pre_key_pair.public_key.serialize()));
    println!("Kyber pre-key public: {}", hex::encode(kyber_pre_key_pair.public_key.serialize()));
    println!();

    println!("=== Summary ===");
    println!("✅ Identity keys generated for Alice and Bob");
    println!("✅ Pre-keys generated (EC and Kyber)");
    println!("✅ Protocol addresses created");
    println!("✅ Key serialization demonstrated");

    println!("\nNote: This example demonstrates basic key generation for LibSignal.");
    println!("Full session establishment would require:");
    println!("  - Pre-key bundle creation and exchange");
    println!("  - X3DH key agreement protocol");
    println!("  - Double Ratchet session establishment");
    println!("  - Message encryption/decryption");
    println!("  - Session state management");

    Ok(())
} 