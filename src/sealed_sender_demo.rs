//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol::{
    DeviceId, IdentityKeyPair, KeyPair, PreKeyId, ProtocolAddress, SignedPreKeyId, kem,
    PreKeyBundle, KyberPreKeyId, SignalProtocolError, UsePQRatchet, Timestamp,
    IdentityKeyStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore,
    InMemSignalProtocolStore, sealed_sender_encrypt, sealed_sender_decrypt,
    ServerCertificate, SenderCertificate, process_prekey_bundle,
    PreKeyRecord, SignedPreKeyRecord, KyberPreKeyRecord, GenericSignedPreKey,
};
use rand::{Rng, CryptoRng};
use std::time::SystemTime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("=== LibSignal Sealed Sender Example ===\n");

    let mut rng = rand::rng();

    // Device IDs and addresses
    let alice_device_id = DeviceId::new(23).unwrap();
    let bob_device_id = DeviceId::new(42).unwrap();

    let alice_e164 = "+14151111111".to_owned();
    let bob_e164 = "+14151114444".to_owned();

    let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
    let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();

    println!("Setting up participants:");
    println!("Alice: {} (device {})", alice_uuid, alice_device_id);
    println!("Bob:   {} (device {})", bob_uuid, bob_device_id);
    println!();

    let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);

    // Create protocol stores for Alice and Bob
    let mut alice_store = InMemSignalProtocolStore::new(
        IdentityKeyPair::generate(&mut rng),
        rng.random(),
    )?;
    let mut bob_store = InMemSignalProtocolStore::new(
        IdentityKeyPair::generate(&mut rng),
        rng.random(),
    )?;

    println!("✅ Created protocol stores for Alice and Bob");

    let alice_pubkey = *alice_store.get_identity_key_pair().await?.public_key();

    // Create Bob's pre-key bundle
    let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut rng).await?;
    println!("✅ Created Bob's pre-key bundle");

    // Alice processes Bob's pre-key bundle to establish a session
    process_prekey_bundle(
        &bob_uuid_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_pre_key_bundle,
        SystemTime::now(),
        &mut rng,
        UsePQRatchet::Yes,
    )
    .await?;

    println!("✅ Alice established session with Bob");

    // Set up sealed sender certificates
    let trust_root = KeyPair::generate(&mut rng);
    let server_key = KeyPair::generate(&mut rng);

    let server_cert =
        ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

    println!("✅ Created server certificate");

    let expires = Timestamp::from_epoch_millis(1605722925);

    let sender_cert = SenderCertificate::new(
        alice_uuid.clone(),
        Some(alice_e164.clone()),
        alice_pubkey,
        alice_device_id,
        expires,
        server_cert,
        &server_key.private_key,
        &mut rng,
    )?;

    println!("✅ Created sender certificate for Alice");
    println!("   Expires: {}", expires.epoch_millis());
    println!();

    // === SEALED SENDER ENCRYPTION/DECRYPTION ===
    println!("=== Sealed Sender Encryption/Decryption ===");

    let alice_message = vec![1, 2, 3, 23, 99];
    println!("Alice's original message: {:?}", alice_message);

    // Alice encrypts a message using sealed sender
    let alice_ctext = sealed_sender_encrypt(
        &bob_uuid_address,
        &sender_cert,
        &alice_message,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::now(),
        &mut rng,
    )
    .await?;

    println!("✅ Alice encrypted message using sealed sender");
    println!("   Ciphertext length: {} bytes", alice_ctext.len());

    // Bob decrypts the sealed sender message
    let bob_decrypted = sealed_sender_decrypt(
        &alice_ctext,
        &trust_root.public_key,
        expires.sub_millis(1), // Valid timestamp
        Some(bob_e164.clone()),
        bob_uuid.clone(),
        bob_device_id,
        &mut bob_store.identity_store,
        &mut bob_store.session_store,
        &mut bob_store.pre_key_store,
        &bob_store.signed_pre_key_store,
        &mut bob_store.kyber_pre_key_store,
        UsePQRatchet::Yes,
    )
    .await?;

    println!("✅ Bob successfully decrypted the sealed sender message");
    println!("   Decrypted message: {:?}", bob_decrypted.message);
    println!("   Sender UUID: {}", bob_decrypted.sender_uuid);
    println!("   Sender E164: {:?}", bob_decrypted.sender_e164);
    println!("   Sender device ID: {}", bob_decrypted.device_id);

    // Verify the message and metadata
    assert_eq!(bob_decrypted.message, alice_message);
    assert_eq!(bob_decrypted.sender_uuid, alice_uuid);
    assert_eq!(bob_decrypted.sender_e164, Some(alice_e164.clone()));
    assert_eq!(bob_decrypted.device_id, alice_device_id);

    println!("✅ All assertions passed - sealed sender works correctly!");
    println!();

    // === TEST EXPIRED CERTIFICATE ===
    println!("=== Testing Expired Certificate ===");

    let alice_ctext2 = sealed_sender_encrypt(
        &bob_uuid_address,
        &sender_cert,
        &alice_message,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::now(),
        &mut rng,
    )
    .await?;

    // Try to decrypt with an expired timestamp (after certificate expiry)
    let bob_result = sealed_sender_decrypt(
        &alice_ctext2,
        &trust_root.public_key,
        expires.add_millis(11), // Timestamp after expiry
        Some(bob_e164.clone()),
        bob_uuid.clone(),
        bob_device_id,
        &mut bob_store.identity_store,
        &mut bob_store.session_store,
        &mut bob_store.pre_key_store,
        &bob_store.signed_pre_key_store,
        &mut bob_store.kyber_pre_key_store,
        UsePQRatchet::Yes,
    )
    .await;

    match bob_result {
        Err(SignalProtocolError::InvalidSealedSenderMessage(_)) => {
            println!("✅ Correctly rejected message with expired certificate");
        }
        Err(err) => {
            println!("❌ Unexpected error: {}", err);
            return Err(err.into());
        }
        Ok(_) => {
            println!("❌ Should not have decrypted with expired certificate!");
            return Err("Certificate validation failed".into());
        }
    }

    // === TEST WRONG TRUST ROOT ===
    println!("\n=== Testing Wrong Trust Root ===");

    let alice_ctext3 = sealed_sender_encrypt(
        &bob_uuid_address,
        &sender_cert,
        &alice_message,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        SystemTime::now(),
        &mut rng,
    )
    .await?;

    let wrong_trust_root = KeyPair::generate(&mut rng);

    let bob_result2 = sealed_sender_decrypt(
        &alice_ctext3,
        &wrong_trust_root.public_key, // Wrong trust root
        expires.sub_millis(1),
        Some(bob_e164.clone()),
        bob_uuid.clone(),
        bob_device_id,
        &mut bob_store.identity_store,
        &mut bob_store.session_store,
        &mut bob_store.pre_key_store,
        &bob_store.signed_pre_key_store,
        &mut bob_store.kyber_pre_key_store,
        UsePQRatchet::Yes,
    )
    .await;

    match bob_result2 {
        Err(SignalProtocolError::InvalidSealedSenderMessage(_)) => {
            println!("✅ Correctly rejected message with wrong trust root");
        }
        Err(err) => {
            println!("❌ Unexpected error: {}", err);
            return Err(err.into());
        }
        Ok(_) => {
            println!("❌ Should not have decrypted with wrong trust root!");
            return Err("Trust root validation failed".into());
        }
    }

    println!("\n🎉 All sealed sender tests completed successfully!");

    Ok(())
}

// Helper function to create a pre-key bundle for a user
async fn create_pre_key_bundle(
    store: &mut InMemSignalProtocolStore,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<PreKeyBundle, SignalProtocolError> {
    let registration_id = store.get_local_registration_id().await?;
    let device_id = DeviceId::new(42).unwrap(); // Bob's device ID

    // Generate pre-keys
    let pre_key_id = PreKeyId::from(rng.random::<u32>());
    let signed_pre_key_id = SignedPreKeyId::from(rng.random::<u32>());
    let kyber_pre_key_id = KyberPreKeyId::from(rng.random::<u32>());

    let pre_key_pair = KeyPair::generate(rng);
    let signed_pre_key_pair = KeyPair::generate(rng);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);

    let identity_key_pair = store.get_identity_key_pair().await?;

    // Create signatures
    let signed_pre_key_signature = identity_key_pair
        .private_key()
        .calculate_signature(&signed_pre_key_pair.public_key.serialize(), rng)?;

    let kyber_pre_key_signature = identity_key_pair
        .private_key()
        .calculate_signature(&kyber_pre_key_pair.public_key.serialize(), rng)?;

    // Create records and store the keys
    let pre_key_record = PreKeyRecord::new(pre_key_id, &pre_key_pair);
    let signed_pre_key_record = SignedPreKeyRecord::new(
        signed_pre_key_id,
        Timestamp::from_epoch_millis(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64),
        &signed_pre_key_pair,
        &signed_pre_key_signature,
    );
    let kyber_pre_key_record = KyberPreKeyRecord::generate(
        kem::KeyType::Kyber1024,
        kyber_pre_key_id,
        identity_key_pair.private_key(),
    )?;

    store.save_pre_key(pre_key_id, &pre_key_record).await?;
    store.save_signed_pre_key(signed_pre_key_id, &signed_pre_key_record).await?;
    store.save_kyber_pre_key(kyber_pre_key_id, &kyber_pre_key_record).await?;

    // Create the bundle
    let bundle = PreKeyBundle::new(
        registration_id,
        device_id,
        Some((pre_key_id, pre_key_pair.public_key)),
        signed_pre_key_id,
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        kyber_pre_key_id,
        kyber_pre_key_record.public_key()?.clone(),
        kyber_pre_key_record.signature()?.to_vec(),
        identity_key_pair.identity_key().clone(),
    )?;

    Ok(bundle)
}
