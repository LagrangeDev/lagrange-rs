use rand::Rng;

const TEA_DELTA: u32 = 0x9E3779B9;
const TEA_ROUNDS: u32 = 16;

/// TEA (Tiny Encryption Algorithm) provider
/// Implements TEA cipher with CBC mode and padding
pub struct TeaProvider;

impl TeaProvider {
    /// Encrypts data using TEA cipher with the given 16-byte key
    /// Returns encrypted data with random padding
    pub fn encrypt(source: &[u8], key: &[u8; 16]) -> Vec<u8> {
        // Calculate padding length: 10 - ((source.len() + 1) & 7)
        // Result is in range 3-10
        let fill = 10 - ((source.len() + 1) & 7);

        // Total length: fill + source + 7 (trailing bytes)
        let total_len = fill + source.len() + 7;

        let mut buffer = Vec::with_capacity(total_len);
        let mut rng = rand::thread_rng();

        // First byte: encode padding length as (fill - 3) | 0xF8
        // fill - 3 gives range 0-7, which fits in 3 bits
        buffer.push(((fill - 3) as u8) | 0xF8);

        // Remaining fill-1 random bytes
        for _ in 1..fill {
            buffer.push(rng.gen());
        }

        // Source data
        buffer.extend_from_slice(source);

        // Fill with 7 zero bytes
        buffer.extend_from_slice(&[0u8; 7]);

        // The total should already be a multiple of 8
        debug_assert_eq!(buffer.len() % 8, 0);

        // Encrypt using TEA in CBC mode
        let mut result = Vec::with_capacity(buffer.len());
        let mut prev_encrypted = [0u8; 8];

        for chunk in buffer.chunks(8) {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);

            // XOR with previous encrypted block (CBC mode)
            for i in 0..8 {
                block[i] ^= prev_encrypted[i];
            }

            // Encrypt block
            let encrypted = Self::encrypt_block(&block, key);
            result.extend_from_slice(&encrypted);
            prev_encrypted = encrypted;
        }

        result
    }

    /// Decrypts data using TEA cipher with the given 16-byte key
    /// Returns decrypted data with padding removed
    pub fn decrypt(source: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
        if source.len() < 16 || !source.len().is_multiple_of(8) {
            return Err("Invalid ciphertext length");
        }

        // Decrypt all blocks
        let mut decrypted = Vec::with_capacity(source.len());
        let mut prev_encrypted = [0u8; 8];

        for chunk in source.chunks(8) {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);

            // Decrypt block
            let mut decrypted_block = Self::decrypt_block(&block, key);

            // XOR with previous encrypted block (CBC mode)
            for i in 0..8 {
                decrypted_block[i] ^= prev_encrypted[i];
            }

            decrypted.extend_from_slice(&decrypted_block);
            prev_encrypted = block;
        }

        // Extract fill length from first byte: (byte & 7) + 3
        let fill = ((decrypted[0] & 0x07) + 3) as usize;

        // Validate fill length
        if fill + 7 > decrypted.len() {
            return Err("Invalid padding length");
        }

        // Extract plaintext (skip fill bytes, remove last 7 bytes)
        let start = fill;
        let end = decrypted.len() - 7;

        if start > end {
            return Err("Invalid decrypted data");
        }

        Ok(decrypted[start..end].to_vec())
    }

    /// Encrypts a single 8-byte block using TEA
    #[inline]
    fn encrypt_block(block: &[u8; 8], key: &[u8; 16]) -> [u8; 8] {
        let mut v0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        let mut v1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);

        let k0 = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
        let k1 = u32::from_be_bytes([key[4], key[5], key[6], key[7]]);
        let k2 = u32::from_be_bytes([key[8], key[9], key[10], key[11]]);
        let k3 = u32::from_be_bytes([key[12], key[13], key[14], key[15]]);

        let mut sum = 0u32;

        for _ in 0..TEA_ROUNDS {
            sum = sum.wrapping_add(TEA_DELTA);
            v0 = v0.wrapping_add(
                ((v1 << 4).wrapping_add(k0))
                    ^ (v1.wrapping_add(sum))
                    ^ ((v1 >> 5).wrapping_add(k1)),
            );
            v1 = v1.wrapping_add(
                ((v0 << 4).wrapping_add(k2))
                    ^ (v0.wrapping_add(sum))
                    ^ ((v0 >> 5).wrapping_add(k3)),
            );
        }

        let mut result = [0u8; 8];
        result[0..4].copy_from_slice(&v0.to_be_bytes());
        result[4..8].copy_from_slice(&v1.to_be_bytes());
        result
    }

    /// Decrypts a single 8-byte block using TEA
    #[inline]
    fn decrypt_block(block: &[u8; 8], key: &[u8; 16]) -> [u8; 8] {
        let mut v0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        let mut v1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);

        let k0 = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
        let k1 = u32::from_be_bytes([key[4], key[5], key[6], key[7]]);
        let k2 = u32::from_be_bytes([key[8], key[9], key[10], key[11]]);
        let k3 = u32::from_be_bytes([key[12], key[13], key[14], key[15]]);

        let mut sum = TEA_DELTA.wrapping_mul(TEA_ROUNDS);

        for _ in 0..TEA_ROUNDS {
            v1 = v1.wrapping_sub(
                ((v0 << 4).wrapping_add(k2))
                    ^ (v0.wrapping_add(sum))
                    ^ ((v0 >> 5).wrapping_add(k3)),
            );
            v0 = v0.wrapping_sub(
                ((v1 << 4).wrapping_add(k0))
                    ^ (v1.wrapping_add(sum))
                    ^ ((v1 >> 5).wrapping_add(k1)),
            );
            sum = sum.wrapping_sub(TEA_DELTA);
        }

        let mut result = [0u8; 8];
        result[0..4].copy_from_slice(&v0.to_be_bytes());
        result[4..8].copy_from_slice(&v1.to_be_bytes());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tea_encrypt_decrypt() {
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let plaintext = b"Hello, World!";

        let encrypted = TeaProvider::encrypt(plaintext, &key);
        let decrypted = TeaProvider::decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tea_empty_data() {
        let key = [0x42; 16];
        let plaintext = b"";

        let encrypted = TeaProvider::encrypt(plaintext, &key);
        let decrypted = TeaProvider::decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tea_various_lengths() {
        let key = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00,
        ];

        for len in 0..100 {
            let plaintext = vec![0x42u8; len];
            let encrypted = TeaProvider::encrypt(&plaintext, &key);
            let decrypted = TeaProvider::decrypt(&encrypted, &key).unwrap();
            assert_eq!(decrypted, plaintext, "Failed at length {}", len);
        }
    }

    #[test]
    fn test_tea_block_encrypt_decrypt() {
        let key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let block = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

        let encrypted = TeaProvider::encrypt_block(&block, &key);
        let decrypted = TeaProvider::decrypt_block(&encrypted, &key);

        assert_eq!(decrypted, block);
    }

    #[test]
    fn test_tea_invalid_length() {
        let key = [0x42; 16];
        let invalid = vec![0u8; 7]; // Not multiple of 8

        assert!(TeaProvider::decrypt(&invalid, &key).is_err());
    }
}
