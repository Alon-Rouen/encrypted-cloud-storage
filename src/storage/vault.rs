use std::path::{Path, PathBuf};
use std::fs;
use anyhow::Result;
use crate::crypto::aead;
use crate::storage::manifest::Manifest;

const MANIFEST_FILENAME: &str = "manifest.enc";

pub struct Vault {
    root: PathBuf,
}

impl Vault {
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)
            .map_err(|e| anyhow::anyhow!("Cannot create vault at {:?}: {}", root, e))?;
        Ok(Self { root: root.to_path_buf() })
    }
    pub fn store_blob(&self, id: &str, data: &[u8]) -> Result<()> {
        self.validate_id(id)?;
        fs::write(self.root.join(id), data)
            .map_err(|e| anyhow::anyhow!("Failed to write blob {}: {}", id, e))
    }
    pub fn fetch_blob(&self, id: &str) -> Result<Vec<u8>> {
        self.validate_id(id)?;
        let path = self.root.join(id);
        if !path.exists() { anyhow::bail!("Blob '{}' not found in vault", id); }
        fs::read(path).map_err(|e| anyhow::anyhow!("Failed to read blob {}: {}", id, e))
    }
    pub fn delete_blob(&self, id: &str) -> Result<()> {
        self.validate_id(id)?;
        let path = self.root.join(id);
        if path.exists() {
            fs::remove_file(path)
                .map_err(|e| anyhow::anyhow!("Failed to delete blob {}: {}", id, e))?;
        }
        Ok(())
    }
    pub fn save_manifest(&self, meta_key: &[u8; 32], manifest: &Manifest) -> Result<()> {
        let json = serde_json::to_vec(manifest)
            .map_err(|e| anyhow::anyhow!("Manifest serialization failed: {}", e))?;
        let encrypted = aead::encrypt(meta_key, &json)?;
        fs::write(self.root.join(MANIFEST_FILENAME), encrypted)
            .map_err(|e| anyhow::anyhow!("Failed to write manifest: {}", e))
    }
    pub fn load_manifest(&self, meta_key: &[u8; 32]) -> Result<Manifest> {
        let path = self.root.join(MANIFEST_FILENAME);
        if !path.exists() { return Ok(Manifest::new()); }
        let data = fs::read(&path)
            .map_err(|e| anyhow::anyhow!("Failed to read manifest: {}", e))?;
        let json = aead::decrypt(meta_key, &data)
            .map_err(|_| anyhow::anyhow!("Manifest decryption failed - wrong password or tampered"))?;
        serde_json::from_slice(&json)
            .map_err(|e| anyhow::anyhow!("Manifest deserialization failed: {}", e))
    }
    fn validate_id(&self, id: &str) -> Result<()> {
        if id.contains('/') || id.contains('\\') || id.contains("..") {
            anyhow::bail!("Invalid storage id: '{}'", id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::storage::manifest::FileEntry;

    fn test_key() -> [u8; 32] { [0xABu8; 32] }

    #[test]
    fn store_and_fetch_blob() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.store_blob("test-uuid", b"encrypted data").unwrap();
        assert_eq!(vault.fetch_blob("test-uuid").unwrap(), b"encrypted data");
    }
    #[test]
    fn fetch_missing_blob_errors() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        assert!(vault.fetch_blob("nonexistent").is_err());
    }
    #[test]
    fn manifest_roundtrip() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        let key = test_key();
        let mut m = Manifest::new();
        m.upsert("hello.txt", FileEntry { storage_id: "uuid-abc".into(), size: 5, uploaded_at: 0 });
        vault.save_manifest(&key, &m).unwrap();
        let loaded = vault.load_manifest(&key).unwrap();
        assert!(loaded.get("hello.txt").is_some());
    }
    #[test]
    fn wrong_key_fails_manifest_load() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        vault.save_manifest(&[0xAAu8; 32], &Manifest::new()).unwrap();
        assert!(vault.load_manifest(&[0xBBu8; 32]).is_err());
    }
    #[test]
    fn path_traversal_rejected() {
        let dir = tempdir().unwrap();
        let vault = Vault::open(dir.path()).unwrap();
        assert!(vault.store_blob("../../etc/passwd", b"x").is_err());
    }
}
