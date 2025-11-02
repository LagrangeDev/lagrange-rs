use rand::Rng;

/// Encrypts data using TEA (Tiny Encryption Algorithm)
pub fn encrypt(source: &[u8], key: &[u8; 16]) -> Vec<u8> {
        let k0 = u32::from_be_bytes(key[0..4].try_into().unwrap());
        let k1 = u32::from_be_bytes(key[4..8].try_into().unwrap());
        let k2 = u32::from_be_bytes(key[8..12].try_into().unwrap());
        let k3 = u32::from_be_bytes(key[12..16].try_into().unwrap());

        let fill = 10 - ((source.len() + 1) & 7);
        let total_len = fill + source.len() + 7;

        let mut buffer = Vec::with_capacity(total_len);
        let mut rng = rand::thread_rng();

        buffer.push(((fill - 3) as u8) | 0xF8);

        for _ in 1..fill {
            buffer.push(rng.gen());
        }
        buffer.extend_from_slice(source);
        buffer.extend_from_slice(&[0u8; 7]);

        debug_assert_eq!(buffer.len() % 8, 0);

        let mut plain_xor = 0u64;
        let mut prev_xor = 0u64;

        for i in (0..buffer.len()).step_by(8) {
            let block = u64::from_be_bytes(buffer[i..i + 8].try_into().unwrap());
            let plain = block ^ plain_xor;

            let mut x = (plain >> 32) as u32;
            let mut y = plain as u32;

            x = x.wrapping_add(y.wrapping_add(0x9e3779b9u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0x9e3779b9u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0x3c6ef372u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0x3c6ef372u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0xdaa66d2bu32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0xdaa66d2bu32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0x78dde6e4u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0x78dde6e4u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0x1715609du32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0x1715609du32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0xb54cda56u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0xb54cda56u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0x5384540fu32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0x5384540fu32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0xf1bbcdc8u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0xf1bbcdc8u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0x8ff34781u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0x8ff34781u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0x2e2ac13au32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0x2e2ac13au32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0xcc623af3u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0xcc623af3u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0x6a99b4acu32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0x6a99b4acu32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0x08d12e65u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0x08d12e65u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0xa708a81eu32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0xa708a81eu32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0x454021d7u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0x454021d7u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_add(y.wrapping_add(0xe3779b90u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_add(x.wrapping_add(0xe3779b90u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));

            let encrypted = ((x as u64) << 32) | (y as u64);
            plain_xor = encrypted ^ prev_xor;
            prev_xor = plain;

            let bytes = plain_xor.to_be_bytes();
            buffer[i..i + 8].copy_from_slice(&bytes);
        }

        buffer
}

/// Decrypts data using TEA (Tiny Encryption Algorithm)
pub fn decrypt(source: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
        if source.len() < 16 || !source.len().is_multiple_of(8) {
            return Err("Invalid ciphertext length");
        }

        let k0 = u32::from_be_bytes(key[0..4].try_into().unwrap());
        let k1 = u32::from_be_bytes(key[4..8].try_into().unwrap());
        let k2 = u32::from_be_bytes(key[8..12].try_into().unwrap());
        let k3 = u32::from_be_bytes(key[12..16].try_into().unwrap());

        let mut decrypted = vec![0u8; source.len()];
        let mut plain_xor = 0u64;
        let mut prev_xor = 0u64;

        for i in (0..source.len()).step_by(8) {
            let block = u64::from_be_bytes(source[i..i + 8].try_into().unwrap());
            plain_xor ^= block;

            let mut x = (plain_xor >> 32) as u32;
            let mut y = plain_xor as u32;

            y = y.wrapping_sub(x.wrapping_add(0xe3779b90u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0xe3779b90u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0x454021d7u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0x454021d7u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0xa708a81eu32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0xa708a81eu32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0x08d12e65u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0x08d12e65u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0x6a99b4acu32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0x6a99b4acu32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0xcc623af3u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0xcc623af3u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0x2e2ac13au32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0x2e2ac13au32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0x8ff34781u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0x8ff34781u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0xf1bbcdc8u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0xf1bbcdc8u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0x5384540fu32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0x5384540fu32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0xb54cda56u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0xb54cda56u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0x1715609du32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0x1715609du32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0x78dde6e4u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0x78dde6e4u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0xdaa66d2bu32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0xdaa66d2bu32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0x3c6ef372u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0x3c6ef372u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));
            y = y.wrapping_sub(x.wrapping_add(0x9e3779b9u32) ^ ((x << 4).wrapping_add(k2)) ^ ((x >> 5).wrapping_add(k3)));
            x = x.wrapping_sub(y.wrapping_add(0x9e3779b9u32) ^ ((y << 4).wrapping_add(k0)) ^ ((y >> 5).wrapping_add(k1)));

            plain_xor = ((x as u64) << 32) | (y as u64);
            let output = plain_xor ^ prev_xor;
            prev_xor = block;

            let bytes = output.to_be_bytes();
            decrypted[i..i + 8].copy_from_slice(&bytes);
        }

        let fill = ((decrypted[0] & 0x07) + 3) as usize;

        if fill + 7 > decrypted.len() {
            return Err("Invalid padding length");
        }

        let start = fill;
        let end = decrypted.len() - 7;

        if start > end {
            return Err("Invalid decrypted data");
        }

        Ok(decrypted[start..end].to_vec())
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

        let encrypted = encrypt(plaintext, &key);
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tea_empty_data() {
        let key = [0x42; 16];
        let plaintext = b"";

        let encrypted = encrypt(plaintext, &key);
        let decrypted = decrypt(&encrypted, &key).unwrap();

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
            let encrypted = encrypt(&plaintext, &key);
            let decrypted = decrypt(&encrypted, &key).unwrap();
            assert_eq!(decrypted, plaintext, "Failed at length {}", len);
        }
    }


    #[test]
    fn test_tea_invalid_length() {
        let key = [0x42; 16];
        let invalid = vec![0u8; 7]; // Not multiple of 8

        assert!(decrypt(&invalid, &key).is_err());
    }
}
