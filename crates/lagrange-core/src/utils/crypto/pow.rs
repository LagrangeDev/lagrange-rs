use crate::utils::BinaryPacket;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::time::Instant;

const MAX_ITERATIONS: u64 = 6_000_000;

/// Generates TLV547 response from TLV546 input
/// Performs SHA256-based proof-of-work calculation
pub fn generate_tlv547(tlv546: &[u8]) -> Result<Vec<u8>, String> {
        let mut packet = BinaryPacket::from_slice(tlv546);

        let version = packet.read::<u16>().map_err(|e| e.to_string())?;
        let pow_type = packet.read::<u32>().map_err(|e| e.to_string())?;
        let hash_type = packet.read::<u8>().map_err(|e| e.to_string())?;
        let target_len = packet.read::<u16>().map_err(|e| e.to_string())? as usize;
        let target = packet
            .read_bytes(target_len)
            .map_err(|e| e.to_string())?
            .to_vec();

        let data_len = packet.read::<u16>().map_err(|e| e.to_string())? as usize;
        let data = packet
            .read_bytes(data_len)
            .map_err(|e| e.to_string())?
            .to_vec();

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
            if hash_matches_target(&hash, &target) {
                found = true;
                break;
            }

            nonce += 1u32;
            iterations += 1;
        }

        if !found {
            return Err(format!(
                "PoW failed: exceeded maximum iterations ({})",
                effective_max
            ));
        }

        let elapsed_ms = start_time.elapsed().as_millis() as u64;

        // Build TLV547 response
        let mut response = BinaryPacket::with_capacity(256);
        response.write(version);
        response.write(pow_type);
        response.write(hash_type);

        // Write nonce
        let nonce_bytes = nonce.to_bytes_be();
        response.write(nonce_bytes.len() as u16);
        response.write_bytes(&nonce_bytes);

        // Write timing and iteration info
        response.write(elapsed_ms).write(iterations);

        Ok(response.to_vec())
}

/// Generates TLV548 response
/// Creates test data and calls generate_tlv547
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
        let target = Sha256::digest(test_bytes);

        // Build TLV546 input for TLV547
        let mut tlv546 = BinaryPacket::with_capacity(256);
        tlv546.write(1u16); // version
        tlv546.write(1u32); // type
        tlv546.write(1u8); // hash_type
        tlv546.write(target.len() as u16);
        tlv546.write_bytes(&target);
        tlv546.write(random_bytes.len() as u16);
        tlv546.write_bytes(&random_bytes);
        tlv546.write(MAX_ITERATIONS);

        generate_tlv547(&tlv546.to_vec())
}

/// Checks if a hash matches the target
/// Compares hash prefix with target
fn hash_matches_target(hash: &[u8], target: &[u8]) -> bool {
    let compare_len = target.len().min(hash.len());
    hash[..compare_len] == target[..compare_len]
}
