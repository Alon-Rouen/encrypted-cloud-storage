use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;
use anyhow::Result;

pub const KEY_LEN: usize = 32;

pub struct SessionKeys {
    pub file_key: [u8; KEY_LEN],
    pub meta_key: [u8; KEY_LEN],
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.file_key.zeroize();
        self.meta_key.zeroize();
    }
}

pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(info, &mut okm)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(okm)
}

pub fn derive_session_keys(ikm: &[u8], salt: &[u8]) -> Result<SessionKeys> {
    let file_key = derive_key(ikm, salt, b"ecs-file-encryption-v1")?;
    let meta_key = derive_key(ikm, salt, b"ecs-metadata-encryption-v1")?;
    Ok(SessionKeys { file_key, meta_key })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_inputs_give_same_key() {
        let ikm  = b"master-secret-bytes";
        let salt = b"random-salt-32-bytes-padded-here";
        assert_eq!(derive_key(ikm, salt, b"file").unwrap(), derive_key(ikm, salt, b"file").unwrap());
    }
    #[test]
    fn different_info_gives_different_key() {
        let ikm  = b"master-secret-bytes";
        let salt = b"random-salt-32-bytes-padded-here";
        assert_ne!(derive_key(ikm, salt, b"ecs-file-encryption-v1").unwrap(),
                   derive_key(ikm, salt, b"ecs-metadata-encryption-v1").unwrap());
    }
    #[test]
    fn different_salt_gives_different_key() {
        let ikm = b"same-password-bytes";
        assert_ne!(derive_key(ikm, b"salt-for-user-alice-padded-here!", b"file").unwrap(),
                   derive_key(ikm, b"salt-for-user-bob--padded-here!!", b"file").unwrap());
    }
}
