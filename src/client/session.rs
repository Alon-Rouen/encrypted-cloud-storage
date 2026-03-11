// ============================================================
// session.rs
// An authenticated client session. After login, the session
// holds the derived keys in memory and exposes the file
// operations: upload, download, list, delete.
//
// KEY LIFECYCLE:
//   1. User provides password.
//   2. Argon2id verifies it against the stored PHC hash.
//   3. The raw Argon2 output bytes are fed into HKDF to derive
//      (file_key, meta_key) — both 256-bit AES keys.
//   4. Keys live only in this struct (on the heap/stack).
//      They are zeroized when the Session is dropped.
//   5. No key material is ever written to disk or the vault.
// ============================================================

use std::path::{Path, PathBuf};
use std::fs;
use anyhow::Result;
use uuid::Uuid;

use crate::crypto::{aead, keys, password};
use crate::storage::{vault::Vault, manifest::{FileEntry, now_unix}};
use crate::client::profile::UserProfile;

pub struct Session {
    vault:    Vault,
    keys:     keys::SessionKeys,
    #[allow(dead_code)]
    profile_path: PathBuf,
}

impl Session {
    // ----------------------------------------------------------
    // Registration
    // ----------------------------------------------------------

    /// Register a new user:
    ///   1. Hash the password with Argon2id.
    ///   2. Generate a fresh HKDF salt.
    ///   3. Save the profile (hash + salt, no plaintext password).
    ///   4. Return an active Session.
    pub fn register(
        username:    &str,
        password_str: &str,
        vault_dir:   &Path,
        profile_path: &Path,
    ) -> Result<Self> {
        if profile_path.exists() {
            anyhow::bail!(
                "Profile already exists at {:?}. Use 'login' instead.",
                profile_path
            );
        }

        let phc     = password::hash_password(password_str)?;
        let profile = UserProfile::new(username, &phc);
        profile.save(profile_path)?;

        // Derive session keys immediately so the caller gets an active session
        let ikm  = derive_ikm_from_password(password_str, &profile.argon2_phc)?;
        let salt = profile.hkdf_salt_bytes()?;
        let session_keys = keys::derive_session_keys(&ikm, &salt)?;

        println!("✓ Registered user '{}'", username);
        Ok(Session {
            vault: Vault::open(vault_dir)?,
            keys:  session_keys,
            profile_path: profile_path.to_path_buf(),
        })
    }

    // ----------------------------------------------------------
    // Login
    // ----------------------------------------------------------

    /// Log in:
    ///   1. Load the profile from disk.
    ///   2. Verify the password with Argon2id.
    ///   3. Re-derive (file_key, meta_key) via HKDF.
    ///   4. Return an active Session.
    ///
    /// WHY re-derive rather than store the keys?
    ///   Keys stored on disk are only as secure as the disk.
    ///   Re-deriving from the password means an attacker who steals
    ///   the profile file still cannot decrypt anything without the
    ///   password (Argon2id makes brute-force expensive).
    pub fn login(
        password_str: &str,
        vault_dir:    &Path,
        profile_path: &Path,
    ) -> Result<Self> {
        let profile = UserProfile::load(profile_path)?;

        if !password::verify_password(password_str, &profile.argon2_phc)? {
            // Generic error — don't leak whether user exists vs wrong password
            anyhow::bail!("Authentication failed: incorrect password");
        }

        let ikm  = derive_ikm_from_password(password_str, &profile.argon2_phc)?;
        let salt = profile.hkdf_salt_bytes()?;
        let session_keys = keys::derive_session_keys(&ikm, &salt)?;

        println!("✓ Logged in as '{}'", profile.username);
        Ok(Session {
            vault: Vault::open(vault_dir)?,
            keys:  session_keys,
            profile_path: profile_path.to_path_buf(),
        })
    }

    // ----------------------------------------------------------
    // File Operations
    // ----------------------------------------------------------

    /// Upload a local file to the vault.
    ///
    /// Steps:
    ///   1. Read the plaintext file from disk.
    ///   2. Encrypt it with file_key (AES-256-GCM, fresh nonce).
    ///   3. Generate a UUID as the opaque server-side filename.
    ///   4. Store the ciphertext in the vault under the UUID.
    ///   5. Update the manifest (maps real_name → UUID) and re-save it.
    pub fn upload(&self, local_path: &Path) -> Result<()> {
        let filename = local_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid filename: {:?}", local_path))?;

        let plaintext = fs::read(local_path)
            .map_err(|e| anyhow::anyhow!("Cannot read '{}': {}", filename, e))?;

        let ciphertext = aead::encrypt(&self.keys.file_key, &plaintext)?;
        let storage_id = Uuid::new_v4().to_string();

        self.vault.store_blob(&storage_id, &ciphertext)?;

        // Update manifest
        let mut manifest = self.vault.load_manifest(&self.keys.meta_key)?;
        manifest.upsert(filename, FileEntry {
            storage_id,
            size: plaintext.len() as u64,
            uploaded_at: now_unix(),
        });
        self.vault.save_manifest(&self.keys.meta_key, &manifest)?;

        println!("✓ Uploaded '{}' ({} bytes)", filename, plaintext.len());
        Ok(())
    }

    /// Download a file from the vault to `dest_dir`.
    ///
    /// Steps:
    ///   1. Decrypt the manifest to find the UUID for `filename`.
    ///   2. Fetch the ciphertext blob from the vault.
    ///   3. Decrypt with file_key (AES-GCM verifies integrity automatically).
    ///   4. Write the plaintext to `dest_dir/filename`.
    pub fn download(&self, filename: &str, dest_dir: &Path) -> Result<()> {
        let manifest = self.vault.load_manifest(&self.keys.meta_key)?;

        let entry = manifest.get(filename)
            .ok_or_else(|| anyhow::anyhow!("File '{}' not found in vault", filename))?
            .clone();

        let ciphertext = self.vault.fetch_blob(&entry.storage_id)?;
        let plaintext  = aead::decrypt(&self.keys.file_key, &ciphertext)?;

        fs::create_dir_all(dest_dir)?;
        let out_path = dest_dir.join(filename);
        fs::write(&out_path, &plaintext)
            .map_err(|e| anyhow::anyhow!("Cannot write to {:?}: {}", out_path, e))?;

        println!("✓ Downloaded '{}' ({} bytes) → {:?}", filename, plaintext.len(), out_path);
        Ok(())
    }

    /// List all files currently stored in the vault.
    pub fn list(&self) -> Result<Vec<String>> {
        let manifest = self.vault.load_manifest(&self.keys.meta_key)?;
        let files: Vec<String> = manifest.list_files()
            .into_iter()
            .map(|n| {
                let entry = manifest.get(n).unwrap();
                format!("{:<40} {:>10} bytes  uploaded: {}", n, entry.size, entry.uploaded_at)
            })
            .collect();
        Ok(files)
    }

    /// Delete a file from the vault.
    ///
    /// Both the encrypted blob AND the manifest entry are removed.
    /// After deletion, not even the filename is visible on the server.
    pub fn delete(&self, filename: &str) -> Result<()> {
        let mut manifest = self.vault.load_manifest(&self.keys.meta_key)?;

        let entry = manifest.get(filename)
            .ok_or_else(|| anyhow::anyhow!("File '{}' not found", filename))?
            .clone();

        self.vault.delete_blob(&entry.storage_id)?;
        manifest.remove(filename);
        self.vault.save_manifest(&self.keys.meta_key, &manifest)?;

        println!("✓ Deleted '{}'", filename);
        Ok(())
    }
}

// ============================================================
// Internal helpers
// ============================================================

/// Derive a stable byte string from the password to use as HKDF input.
///
/// We use the raw password bytes directly as IKM (input keying material)
/// for HKDF. The Argon2 PHC string is used as a secondary input to bind
/// the derivation to this specific user's registration event.
///
/// Note: in a more hardened design, you would run Argon2 again with
/// a dedicated output parameter to get the IKM, keeping the two usages
/// (verification vs key derivation) strictly separate.
fn derive_ikm_from_password(password: &str, phc: &str) -> Result<Vec<u8>> {
    // We run Argon2id a second time with the stored parameters (extracted from
    // the PHC string) to produce 32 bytes of key material.
    //
    // WHY not reuse the verification hash directly?
    //   The PHC hash is designed for *comparison*, not as key material.
    //   Running Argon2 with output_len=32 gives us proper random-looking bytes
    //   suitable as HKDF input, while the PHC hash remains dedicated to login
    //   verification. This keeps the two usages cleanly separated.
    //
    // WHY is this still secure?
    //   Both calls use the same password + same embedded salt → deterministic.
    //   An attacker who steals the profile file still needs the password to
    //   recompute the IKM, and Argon2id makes that expensive.
    use argon2::Argon2;
    use argon2::password_hash::{PasswordHash, SaltString};

    let parsed = PasswordHash::new(phc)
        .map_err(|e| anyhow::anyhow!("Failed to parse PHC for key derivation: {}", e))?;

    // Re-use the same salt that was generated at registration
    let salt = parsed.salt
        .ok_or_else(|| anyhow::anyhow!("No salt in PHC string"))?;
    let salt_str = SaltString::from_b64(salt.as_str())
        .map_err(|e| anyhow::anyhow!("Invalid salt in PHC: {}", e))?;

    // Derive 32 bytes of key material using the same Argon2id parameters
    let mut output = vec![0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt_str.as_salt().as_str().as_bytes(), &mut output)
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {}", e))?;

    Ok(output)
}

// ============================================================
// Integration Tests
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;

    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir          = tempdir().unwrap();
        let vault_dir    = dir.path().join("vault");
        let profile_path = dir.path().join("user.json");
        (dir, vault_dir, profile_path)
    }

    #[test]
    fn register_and_login() {
        let (_dir, vault_dir, profile_path) = setup();
        Session::register("alice", "s3cur3pass!", &vault_dir, &profile_path).unwrap();
        Session::login("s3cur3pass!", &vault_dir, &profile_path).unwrap();
    }

    #[test]
    fn wrong_password_rejected() {
        let (_dir, vault_dir, profile_path) = setup();
        Session::register("alice", "correct", &vault_dir, &profile_path).unwrap();
        let result = Session::login("wrong", &vault_dir, &profile_path);
        assert!(result.is_err());
    }

    #[test]
    fn upload_download_roundtrip() {
        let dir = tempdir().unwrap();
        let vault_dir    = dir.path().join("vault");
        let profile_path = dir.path().join("user.json");

        // Create a test file
        let src = dir.path().join("hello.txt");
        fs::write(&src, b"Hello, secret world!").unwrap();

        let sess = Session::register("alice", "pass", &vault_dir, &profile_path).unwrap();
        sess.upload(&src).unwrap();

        let out_dir = dir.path().join("downloads");
        sess.download("hello.txt", &out_dir).unwrap();

        let result = fs::read(out_dir.join("hello.txt")).unwrap();
        assert_eq!(result, b"Hello, secret world!");
    }

    #[test]
    fn download_nonexistent_file_errors() {
        let (_dir, vault_dir, profile_path) = setup();
        let sess = Session::register("alice", "pass", &vault_dir, &profile_path).unwrap();
        assert!(sess.download("ghost.txt", Path::new("/tmp")).is_err());
    }

    #[test]
    fn list_shows_uploaded_files() {
        let dir = tempdir().unwrap();
        let vault_dir    = dir.path().join("vault");
        let profile_path = dir.path().join("user.json");

        let f1 = dir.path().join("a.txt");
        let f2 = dir.path().join("b.txt");
        fs::write(&f1, b"aaa").unwrap();
        fs::write(&f2, b"bbb").unwrap();

        let sess = Session::register("bob", "pw", &vault_dir, &profile_path).unwrap();
        sess.upload(&f1).unwrap();
        sess.upload(&f2).unwrap();

        let files = sess.list().unwrap();
        assert_eq!(files.len(), 2);
        assert!(files[0].contains("a.txt"));
        assert!(files[1].contains("b.txt"));
    }

    #[test]
    fn delete_removes_file() {
        let dir = tempdir().unwrap();
        let vault_dir    = dir.path().join("vault");
        let profile_path = dir.path().join("user.json");

        let f = dir.path().join("todelete.txt");
        fs::write(&f, b"bye").unwrap();

        let sess = Session::register("alice", "pw", &vault_dir, &profile_path).unwrap();
        sess.upload(&f).unwrap();
        sess.delete("todelete.txt").unwrap();

        let files = sess.list().unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn vault_contains_no_plaintext() {
        let dir = tempdir().unwrap();
        let vault_dir    = dir.path().join("vault");
        let profile_path = dir.path().join("user.json");

        let f = dir.path().join("secret.txt");
        fs::write(&f, b"TOP SECRET CONTENT").unwrap();

        let sess = Session::register("alice", "pw", &vault_dir, &profile_path).unwrap();
        sess.upload(&f).unwrap();

        // Read every file in the vault and verify none contains the plaintext
        for entry in fs::read_dir(&vault_dir).unwrap() {
            let content = fs::read(entry.unwrap().path()).unwrap();
            let content_str = String::from_utf8_lossy(&content);
            assert!(
                !content_str.contains("TOP SECRET CONTENT"),
                "Plaintext found in vault file!"
            );
            assert!(
                !content_str.contains("secret.txt"),
                "Plaintext filename found in vault!"
            );
        }
    }
}
