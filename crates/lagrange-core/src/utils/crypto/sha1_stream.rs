use sha1::{Digest, Sha1};

/// SHA-1 streaming hash implementation
/// Provides incremental hashing capabilities compatible with the C# implementation
pub struct Sha1Stream {
    hasher: Sha1,
}

impl Sha1Stream {
    /// Creates a new SHA-1 stream hasher
    #[inline]
    pub fn new() -> Self {
        Self {
            hasher: Sha1::new(),
        }
    }

    /// Updates the hash with the given data
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalizes the hash and returns the 20-byte digest
    #[inline]
    pub fn finalize(self) -> [u8; 20] {
        let result = self.hasher.finalize();
        result.into()
    }

    /// Computes the hash of the entire input and returns the 20-byte digest
    #[inline]
    pub fn hash(data: &[u8]) -> [u8; 20] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Resets the hasher to its initial state
    #[inline]
    pub fn reset(&mut self) {
        self.hasher = Sha1::new();
    }
}

impl Default for Sha1Stream {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_empty() {
        let hash = Sha1Stream::hash(b"");
        assert_eq!(
            hash,
            [
                0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
                0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn test_sha1_hello_world() {
        let hash = Sha1Stream::hash(b"Hello, World!");
        assert_eq!(
            hash,
            [
                0x0a, 0x0a, 0x9f, 0x2a, 0x67, 0x72, 0x94, 0x25, 0x57, 0xab, 0x53, 0x55, 0xd7, 0x6a,
                0xf4, 0x42, 0xf8, 0xf6, 0x5e, 0x01
            ]
        );
    }

    #[test]
    fn test_sha1_streaming() {
        let mut hasher = Sha1Stream::new();
        hasher.update(b"Hello, ");
        hasher.update(b"World!");
        let hash = hasher.finalize();

        assert_eq!(
            hash,
            [
                0x0a, 0x0a, 0x9f, 0x2a, 0x67, 0x72, 0x94, 0x25, 0x57, 0xab, 0x53, 0x55, 0xd7, 0x6a,
                0xf4, 0x42, 0xf8, 0xf6, 0x5e, 0x01
            ]
        );
    }

    #[test]
    fn test_sha1_reset() {
        let mut hasher = Sha1Stream::new();
        hasher.update(b"test data");
        hasher.reset();
        hasher.update(b"Hello, World!");
        let hash = hasher.finalize();

        let expected = Sha1Stream::hash(b"Hello, World!");
        assert_eq!(hash, expected);
    }
}
