use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, PasswordHash};
use rand::rngs::OsRng;
use anyhow::Result;

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, phc_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(phc_hash)
        .map_err(|e| anyhow::anyhow!("Failed to parse stored hash: {}", e))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hash_and_verify_correct_password() {
        let hash = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &hash).unwrap());
    }
    #[test]
    fn reject_wrong_password() {
        let hash = hash_password("correct-horse").unwrap();
        assert!(!verify_password("wrong-horse", &hash).unwrap());
    }
    #[test]
    fn two_hashes_of_same_password_differ() {
        let h1 = hash_password("abc").unwrap();
        let h2 = hash_password("abc").unwrap();
        assert_ne!(h1, h2);
    }
}
