// ============================================================
// aead.rs
// Authenticated Encryption with Associated Data (AEAD)
// using AES-256-GCM.
//
// WHY AES-256-GCM?
//   - Provides confidentiality (AES-CTR) AND integrity/authenticity
//     (GHASH authentication tag) in a single primitive.
//   - The 128-bit authentication tag detects any tampering with the
//     ciphertext before we decrypt — if a single bit is flipped on
//     the server, decryption fails loudly instead of silently
//     returning garbage.
//   - Hardware-accelerated on modern CPUs (AES-NI), making it fast.
//
// NONCE STRATEGY:
//   - Each encryption call generates a fresh 96-bit (12-byte) random
//     nonce via OsRng (CSPRNG).
//   - AES-GCM is catastrophically broken if a nonce is reused with
//     the same key — an attacker can recover the key. Random nonces
//     with 96 bits give a collision probability below 2^-32 even
//     after 2^32 encryptions (birthday bound), which is safe in
//     practice for a file storage system.
//
// WIRE FORMAT:  nonce (12 bytes) || ciphertext || tag (16 bytes)
// ============================================================

use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use rand::{RngCore, rngs::OsRng};
use anyhow::Result;

/// Encrypt `plaintext` under `key` using AES-256-GCM.
///
/// A fresh random 96-bit nonce is prepended to the output so the
/// recipient can always recover it for decryption.
///
/// Output layout:
///   [ nonce: 12 bytes | ciphertext + GCM tag: len(plaintext) + 16 bytes ]
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

    // Prepend nonce so decrypt() can always find it
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a blob produced by `encrypt`.
///
/// The GCM tag verification happens inside `cipher.decrypt` —
/// if the data was tampered with (or the wrong key is used),
/// this returns an error BEFORE any plaintext is exposed.
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 + 16 {
        anyhow::bail!(
            "Ciphertext too short ({} bytes): must be at least 28 bytes (nonce + tag)",
            data.len()
        );
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce  = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!(
            "AES-GCM decryption failed — wrong key or data was tampered with"
        ))
}

// ============================================================
// Tests
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] { [0x42u8; 32] }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let plaintext = b"Hello, encrypted world!";
        let ct = encrypt(&test_key(), plaintext).unwrap();
        let pt = decrypt(&test_key(), &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let ct = encrypt(&test_key(), b"secret").unwrap();
        let bad_key = [0x00u8; 32];
        assert!(decrypt(&bad_key, &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let mut ct = encrypt(&test_key(), b"important data").unwrap();
        // Flip a bit in the ciphertext body (after the 12-byte nonce)
        ct[15] ^= 0xFF;
        assert!(decrypt(&test_key(), &ct).is_err());
    }

    #[test]
    fn two_encryptions_produce_different_ciphertexts() {
        // Different nonces → different ciphertexts (semantic security)
        let c1 = encrypt(&test_key(), b"same plaintext").unwrap();
        let c2 = encrypt(&test_key(), b"same plaintext").unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn empty_plaintext_works() {
        let ct = encrypt(&test_key(), b"").unwrap();
        let pt = decrypt(&test_key(), &ct).unwrap();
        assert_eq!(pt, b"");
    }
}