use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes128Gcm, Aes256Gcm, Nonce,
};

/// AES-GCM encryption provider
/// Supports both AES-128-GCM and AES-256-GCM
pub struct AesGcmProvider;

impl AesGcmProvider {
    /// Encrypts plaintext using AES-128-GCM with the given 16-byte key
    /// Returns: [12-byte IV][ciphertext][16-byte auth tag]
    pub fn encrypt_128(plaintext: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
        let cipher = Aes128Gcm::new(key.into());
        Self::encrypt_internal(&cipher, plaintext)
    }

    /// Encrypts plaintext using AES-256-GCM with the given 32-byte key
    /// Returns: [12-byte IV][ciphertext][16-byte auth tag]
    pub fn encrypt_256(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
        let cipher = Aes256Gcm::new(key.into());
        Self::encrypt_internal(&cipher, plaintext)
    }

    /// Decrypts ciphertext using AES-128-GCM with the given 16-byte key
    /// Input format: [12-byte IV][ciphertext][16-byte auth tag]
    pub fn decrypt_128(ciphertext: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
        let cipher = Aes128Gcm::new(key.into());
        Self::decrypt_internal(&cipher, ciphertext)
    }

    /// Decrypts ciphertext using AES-256-GCM with the given 32-byte key
    /// Input format: [12-byte IV][ciphertext][16-byte auth tag]
    pub fn decrypt_256(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
        let cipher = Aes256Gcm::new(key.into());
        Self::decrypt_internal(&cipher, ciphertext)
    }

    /// Internal encryption function
    fn encrypt_internal<C: Aead + AeadCore>(
        cipher: &C,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        // Generate random 12-byte nonce
        let nonce = C::generate_nonce(&mut OsRng);

        // Encrypt plaintext
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| "Encryption failed")?;

        // Construct result: [nonce][ciphertext with tag]
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Internal decryption function
    #[allow(deprecated)] // Suppressing GenericArray::from_slice deprecation until aes-gcm upgrades to generic-array 1.x
    fn decrypt_internal<C: Aead + AeadCore>(
        cipher: &C,
        data: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        // Minimum length: 12-byte nonce + 16-byte tag
        if data.len() < 28 {
            return Err("Invalid ciphertext length");
        }

        // Extract nonce (first 12 bytes)
        let nonce = Nonce::<C::NonceSize>::from_slice(&data[..12]);

        // Extract ciphertext + tag (remaining bytes)
        let ciphertext = &data[12..];

        // Decrypt and verify
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption or authentication failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_128_gcm_encrypt_decrypt() {
        let key = [0x42u8; 16];
        let plaintext = b"Hello, World! This is a test message.";

        let encrypted = AesGcmProvider::encrypt_128(plaintext, &key).unwrap();
        assert!(encrypted.len() >= plaintext.len() + 28); // nonce + tag

        let decrypted = AesGcmProvider::decrypt_128(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_256_gcm_encrypt_decrypt() {
        let key = [0x33u8; 32];
        let plaintext = b"Testing AES-256-GCM encryption and decryption.";

        let encrypted = AesGcmProvider::encrypt_256(plaintext, &key).unwrap();
        assert!(encrypted.len() >= plaintext.len() + 28); // nonce + tag

        let decrypted = AesGcmProvider::decrypt_256(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_empty_plaintext() {
        let key = [0x11u8; 16];
        let plaintext = b"";

        let encrypted = AesGcmProvider::encrypt_128(plaintext, &key).unwrap();
        let decrypted = AesGcmProvider::decrypt_128(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_wrong_key() {
        let key1 = [0x42u8; 16];
        let key2 = [0x43u8; 16];
        let plaintext = b"Secret message";

        let encrypted = AesGcmProvider::encrypt_128(plaintext, &key1).unwrap();
        let result = AesGcmProvider::decrypt_128(&encrypted, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_tampered_ciphertext() {
        let key = [0x55u8; 16];
        let plaintext = b"Original message";

        let mut encrypted = AesGcmProvider::encrypt_128(plaintext, &key).unwrap();

        // Tamper with the ciphertext
        if encrypted.len() > 15 {
            encrypted[15] ^= 0x01;
        }

        let result = AesGcmProvider::decrypt_128(&encrypted, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_invalid_length() {
        let key = [0x77u8; 16];
        let invalid = vec![0u8; 20]; // Too short

        let result = AesGcmProvider::decrypt_128(&invalid, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_nonce_uniqueness() {
        let key = [0x88u8; 16];
        let plaintext = b"Same plaintext";

        let encrypted1 = AesGcmProvider::encrypt_128(plaintext, &key).unwrap();
        let encrypted2 = AesGcmProvider::encrypt_128(plaintext, &key).unwrap();

        // Different nonces should result in different ciphertexts
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same plaintext
        let decrypted1 = AesGcmProvider::decrypt_128(&encrypted1, &key).unwrap();
        let decrypted2 = AesGcmProvider::decrypt_128(&encrypted2, &key).unwrap();
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }
}
