// ============================================================
// profile.rs
// User profile stored locally (or on the "server" public area).
//
// WHAT IS STORED (and why it's safe):
//   - argon2_phc : the Argon2id password hash (PHC format).
//     Argon2id is memory-hard, so an attacker who steals this
//     cannot brute-force it cheaply. The salt is embedded.
//   - hkdf_salt  : a random 32-byte salt for HKDF (hex-encoded).
//     This is NOT secret — its purpose is to make key derivation
//     unique per user so that two users with the same password
//     get completely different file_key / meta_key.
//   - username   : plaintext, for display only.
//
// WHAT IS NEVER STORED:
//   - The plaintext password
//   - The derived keys (file_key, meta_key)
//   - Any plaintext file data
// ============================================================

use serde::{Serialize, Deserialize};
use rand::{RngCore, rngs::OsRng};
use std::path::Path;
use std::fs;
use anyhow::Result;
use hex;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserProfile {
    pub username:    String,
    /// Argon2id PHC string: $argon2id$v=19$m=...$<salt>$<hash>
    pub argon2_phc:  String,
    /// Random 32-byte salt for HKDF, hex-encoded. NOT secret.
    pub hkdf_salt:   String,
}

impl UserProfile {
    /// Create a new profile for `username` with the given Argon2 PHC hash.
    /// Generates a fresh random HKDF salt.
    pub fn new(username: &str, argon2_phc: &str) -> Self {
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        UserProfile {
            username:   username.to_string(),
            argon2_phc: argon2_phc.to_string(),
            hkdf_salt:  hex::encode(salt),
        }
    }

    /// Decode the hex HKDF salt back to bytes.
    pub fn hkdf_salt_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.hkdf_salt)
            .map_err(|e| anyhow::anyhow!("Invalid HKDF salt in profile: {}", e))
    }

    // ----------------------------------------------------------
    // Persistence
    // ----------------------------------------------------------

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)
            .map_err(|e| anyhow::anyhow!("Failed to save profile: {}", e))
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            anyhow::bail!("No profile found at {:?} — have you registered yet?", path);
        }
        let json = fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read profile: {}", e))?;
        serde_json::from_str(&json)
            .map_err(|e| anyhow::anyhow!("Corrupted profile file: {}", e))
    }
}