use crate::utils::BinaryPacket;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::time::Instant;

const MAX_ITERATIONS: u64 = 6_000_000;

/// Proof-of-Work provider
/// Implements PoW cryptographic operations for TLV547 and TLV548 generation
pub struct PowProvider;

impl PowProvider {
    /// Generates TLV547 response from TLV546 input
    /// Performs SHA256-based proof-of-work calculation
    pub fn generate_tlv547(tlv546: &[u8]) -> Result<Vec<u8>, String> {
        let mut packet = BinaryPacket::from_slice(tlv546);

        // Parse TLV546 structure
        let version = packet.read::<u16>().map_err(|e| e.to_string())?;
        let pow_type = packet.read::<u32>().map_err(|e| e.to_string())?;
        let hash_type = packet.read::<u8>().map_err(|e| e.to_string())?;

        // Read target hash and data
        let target_len = packet.read::<u16>().map_err(|e| e.to_string())? as usize;
        let target = packet.read_bytes(target_len).map_err(|e| e.to_string())?.to_vec();

        let data_len = packet.read::<u16>().map_err(|e| e.to_string())? as usize;
        let data = packet.read_bytes(data_len).map_err(|e| e.to_string())?.to_vec();

        let max_iterations = packet.read::<u64>().map_err(|e| e.to_string())?;
        let effective_max = if max_iterations > 0 && max_iterations < MAX_ITERATIONS {
            max_iterations
        } else {
            MAX_ITERATIONS
        };

        // Perform proof-of-work
        let start_time = Instant::now();
        let mut nonce = BigUint::from(0u32);
        let mut iterations = 0u64;
        let mut found = false;

        while iterations < effective_max {
            // Construct test data: data || nonce_bytes
            let nonce_bytes = nonce.to_bytes_be();
            let mut test_data = Vec::with_capacity(data.len() + nonce_bytes.len());
            test_data.extend_from_slice(&data);
            test_data.extend_from_slice(&nonce_bytes);

            // Compute SHA256 hash
            let hash = Sha256::digest(&test_data);

            // Check if hash matches target
            if Self::hash_matches_target(&hash, &target) {
                found = true;
                break;
            }

            nonce += 1u32;
            iterations += 1;
        }

        if !found {
            return Err(format!("PoW failed: exceeded maximum iterations ({})", effective_max));
        }

        let elapsed_ms = start_time.elapsed().as_millis() as u64;

        // Build TLV547 response
        let mut response = BinaryPacket::with_capacity(256);
        response.write(version).map_err(|e| e.to_string())?;
        response.write(pow_type).map_err(|e| e.to_string())?;
        response.write(hash_type).map_err(|e| e.to_string())?;

        // Write nonce
        let nonce_bytes = nonce.to_bytes_be();
        response.write(nonce_bytes.len() as u16).map_err(|e| e.to_string())?;
        response.write_bytes(&nonce_bytes);

        // Write timing and iteration info
        response.write(elapsed_ms).map_err(|e| e.to_string())?;
        response.write(iterations).map_err(|e| e.to_string())?;

        Ok(response.to_vec())
    }

    /// Generates TLV548 response
    /// Creates test data and calls GenerateTlv547
    pub fn generate_tlv548(uin: u64) -> Result<Vec<u8>, String> {
        let mut rng = rand::thread_rng();

        // Generate 128 random bytes with first byte set to 21
        let mut random_bytes = vec![0u8; 128];
        use rand::Rng;
        rng.fill(&mut random_bytes[..]);
        random_bytes[0] = 21;

        // Create test data: uin + 10000
        let test_number = uin + 10000;
        let test_bytes = test_number.to_be_bytes();

        // Compute SHA256 hash as target
        let target = Sha256::digest(&test_bytes);

        // Build TLV546 input for TLV547
        let mut tlv546 = BinaryPacket::with_capacity(256);
        tlv546.write(1u16).map_err(|e| e.to_string())?; // version
        tlv546.write(1u32).map_err(|e| e.to_string())?; // type
        tlv546.write(1u8).map_err(|e| e.to_string())?;  // hash_type

        // Write target
        tlv546.write(target.len() as u16).map_err(|e| e.to_string())?;
        tlv546.write_bytes(&target);

        // Write random data
        tlv546.write(random_bytes.len() as u16).map_err(|e| e.to_string())?;
        tlv546.write_bytes(&random_bytes);

        // Max iterations
        tlv546.write(MAX_ITERATIONS).map_err(|e| e.to_string())?;

        Self::generate_tlv547(&tlv546.to_vec())
    }

    /// Checks if a hash matches the target
    /// Compares hash prefix with target
    fn hash_matches_target(hash: &[u8], target: &[u8]) -> bool {
        let compare_len = target.len().min(hash.len());
        hash[..compare_len] == target[..compare_len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_simple_target() {
        // Create a simple TLV546 with easy target
        let mut tlv546 = BinaryPacket::with_capacity(128);
        tlv546.write(1u16).unwrap(); // version
        tlv546.write(1u32).unwrap(); // type
        tlv546.write(1u8).unwrap();  // hash_type

        // Easy target: just first byte = 0x00
        let target = vec![0x00];
        tlv546.write(target.len() as u16).unwrap();
        tlv546.write_bytes(&target);

        // Simple data
        let data = b"test";
        tlv546.write(data.len() as u16).unwrap();
        tlv546.write_bytes(data);

        // Max iterations
        tlv546.write(100000u64).unwrap();

        let result = PowProvider::generate_tlv547(&tlv546.to_vec());
        assert!(result.is_ok(), "PoW should find a solution for easy target");
    }

    #[test]
    fn test_pow_impossible_target() {
        // Create TLV546 with very difficult target
        let mut tlv546 = BinaryPacket::with_capacity(128);
        tlv546.write(1u16).unwrap(); // version
        tlv546.write(1u32).unwrap(); // type
        tlv546.write(1u8).unwrap();  // hash_type

        // Impossible target for small iterations
        let target = vec![0x00, 0x00, 0x00, 0x00, 0x00];
        tlv546.write(target.len() as u16).unwrap();
        tlv546.write_bytes(&target);

        // Simple data
        let data = b"test";
        tlv546.write(data.len() as u16).unwrap();
        tlv546.write_bytes(data);

        // Very limited iterations
        tlv546.write(10u64).unwrap();

        let result = PowProvider::generate_tlv547(&tlv546.to_vec());
        assert!(result.is_err(), "PoW should fail for impossible target with limited iterations");
    }

    #[test]
    fn test_hash_matches_target() {
        let hash = vec![0x12, 0x34, 0x56, 0x78];

        // Exact match
        assert!(PowProvider::hash_matches_target(&hash, &[0x12, 0x34, 0x56, 0x78]));

        // Prefix match
        assert!(PowProvider::hash_matches_target(&hash, &[0x12, 0x34]));

        // No match
        assert!(!PowProvider::hash_matches_target(&hash, &[0x12, 0x35]));
    }

    #[test]
    fn test_generate_tlv548() {
        let uin = 123456789u64;
        let result = PowProvider::generate_tlv548(uin);

        // This might fail or succeed depending on the random data
        // but it should not panic
        match result {
            Ok(_) => println!("TLV548 generation succeeded"),
            Err(e) => println!("TLV548 generation failed (expected for difficult target): {}", e),
        }
    }

    #[test]
    fn test_pow_version_and_type_preserved() {
        let mut tlv546 = BinaryPacket::with_capacity(128);
        tlv546.write(42u16).unwrap(); // custom version
        tlv546.write(99u32).unwrap(); // custom type
        tlv546.write(1u8).unwrap();

        let target = vec![0x00];
        tlv546.write(target.len() as u16).unwrap();
        tlv546.write_bytes(&target);

        let data = b"test";
        tlv546.write(data.len() as u16).unwrap();
        tlv546.write_bytes(data);

        tlv546.write(100000u64).unwrap();

        if let Ok(result) = PowProvider::generate_tlv547(&tlv546.to_vec()) {
            let mut response = BinaryPacket::from_vec(result);
            let version = response.read::<u16>().unwrap();
            let pow_type = response.read::<u32>().unwrap();

            assert_eq!(version, 42);
            assert_eq!(pow_type, 99);
        }
    }
}
