use super::sha1_stream::Sha1Stream;
use std::io::{Read, Seek, SeekFrom};

const SAMPLE_SIZE: usize = 10 * 1024 * 1024; // 10MB
const THRESHOLD: u64 = 30 * 1024 * 1024; // 30MB

/// Triple SHA-1 provider
/// Computes SHA-1 hash by sampling data from streams or byte arrays
pub struct TriSha1Provider;

impl TriSha1Provider {
    /// Computes TriSha1 hash from a seekable stream
    /// - Files ≤ 30MB: Uses entire content
    /// - Larger files: Takes three 10MB samples from beginning, middle, and end
    pub fn hash_stream<R: Read + Seek>(stream: &mut R) -> std::io::Result<[u8; 20]> {
        // Get the length of the stream
        let length = stream.seek(SeekFrom::End(0))?;
        stream.seek(SeekFrom::Start(0))?;

        let mut buffer = if length <= THRESHOLD {
            // Small file: read entire content
            let mut buf = Vec::with_capacity((length + 8) as usize);
            stream.read_to_end(&mut buf)?;
            buf
        } else {
            // Large file: sample from beginning, middle, and end
            let mut buf = Vec::with_capacity(SAMPLE_SIZE * 3 + 8);

            // Read first 10MB
            stream.seek(SeekFrom::Start(0))?;
            let mut chunk = vec![0u8; SAMPLE_SIZE];
            stream.read_exact(&mut chunk)?;
            buf.extend_from_slice(&chunk);

            // Read middle 10MB
            let middle_offset = (length / 2).saturating_sub((SAMPLE_SIZE / 2) as u64);
            stream.seek(SeekFrom::Start(middle_offset))?;
            stream.read_exact(&mut chunk)?;
            buf.extend_from_slice(&chunk);

            // Read last 10MB
            let end_offset = length.saturating_sub(SAMPLE_SIZE as u64);
            stream.seek(SeekFrom::Start(end_offset))?;
            stream.read_exact(&mut chunk)?;
            buf.extend_from_slice(&chunk);

            buf
        };

        // Append the original length as little-endian u64
        buffer.extend_from_slice(&length.to_le_bytes());

        // Compute SHA-1 hash
        Ok(Sha1Stream::hash(&buffer))
    }

    /// Computes TriSha1 hash from a byte array
    /// - Small data (≤ 30MB): Uses entire content
    /// - Larger data: Samples from beginning, middle, and end
    pub fn hash_bytes(data: &[u8]) -> [u8; 20] {
        let length = data.len() as u64;

        let buffer = if length <= THRESHOLD {
            // Small data: use entire content
            let mut buf = Vec::with_capacity(data.len() + 8);
            buf.extend_from_slice(data);
            buf.extend_from_slice(&length.to_le_bytes());
            buf
        } else {
            // Large data: sample from beginning, middle, and end
            let mut buf = Vec::with_capacity(SAMPLE_SIZE * 3 + 8);

            // First 10MB
            buf.extend_from_slice(&data[..SAMPLE_SIZE]);

            // Middle 10MB
            let middle_offset = (data.len() / 2).saturating_sub(SAMPLE_SIZE / 2);
            buf.extend_from_slice(&data[middle_offset..middle_offset + SAMPLE_SIZE]);

            // Last 10MB
            let end_offset = data.len().saturating_sub(SAMPLE_SIZE);
            buf.extend_from_slice(&data[end_offset..end_offset + SAMPLE_SIZE]);

            // Append original length
            buf.extend_from_slice(&length.to_le_bytes());
            buf
        };

        Sha1Stream::hash(&buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_tri_sha1_small_data() {
        let data = b"Hello, World!";
        let hash = TriSha1Provider::hash_bytes(data);

        // Expected hash includes the length appended
        let mut buf = Vec::from(&data[..]);
        buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        let expected = Sha1Stream::hash(&buf);

        assert_eq!(hash, expected);
    }

    #[test]
    fn test_tri_sha1_small_stream() {
        let data = b"Test data for streaming";
        let mut cursor = Cursor::new(data);
        let hash = TriSha1Provider::hash_stream(&mut cursor).unwrap();

        let expected = TriSha1Provider::hash_bytes(data);
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_tri_sha1_large_data() {
        // Create a 40MB test data
        let large_data = vec![0x42u8; 40 * 1024 * 1024];
        let hash = TriSha1Provider::hash_bytes(&large_data);

        // Verify it's sampling (not using the entire 40MB)
        // The hash should be computed from 30MB of samples + 8 bytes length
        let mut expected_buf = Vec::with_capacity(SAMPLE_SIZE * 3 + 8);

        // First 10MB
        expected_buf.extend_from_slice(&large_data[..SAMPLE_SIZE]);

        // Middle 10MB
        let middle_offset = (large_data.len() / 2).saturating_sub(SAMPLE_SIZE / 2);
        expected_buf.extend_from_slice(&large_data[middle_offset..middle_offset + SAMPLE_SIZE]);

        // Last 10MB
        let end_offset = large_data.len().saturating_sub(SAMPLE_SIZE);
        expected_buf.extend_from_slice(&large_data[end_offset..end_offset + SAMPLE_SIZE]);

        // Append length
        expected_buf.extend_from_slice(&(large_data.len() as u64).to_le_bytes());

        let expected = Sha1Stream::hash(&expected_buf);
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_tri_sha1_threshold() {
        // Test exactly at threshold (30MB)
        let data = vec![0xAAu8; 30 * 1024 * 1024];
        let hash = TriSha1Provider::hash_bytes(&data);

        // Should use entire content
        let mut buf = data.clone();
        buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        let expected = Sha1Stream::hash(&buf);

        assert_eq!(hash, expected);
    }
}
